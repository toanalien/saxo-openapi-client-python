"""
Saxo Bank OpenAPI Python Client.

This module contains the SaxoOpenAPIClient class which is the main interface to interact
with Saxo Bank OpenAPI.
"""

import asyncio
import json
import threading
import webbrowser
from datetime import datetime
from secrets import token_urlsafe
from time import sleep, time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs

from httpx import Client, Response, post
from loguru import logger
from pydantic import AnyHttpUrl, ValidationError, parse_obj_as
from websockets import client as ws_client

from .models import (
    APIEnvironment,
    APIRequestError,
    AuthorizationCode,
    HttpsUrl,
    NotLoggedInError,
    OpenAPIAppConfig,
    TokenData,
    TokenExpiredError,
)
from .redirect_server import RedirectServer
from .utils import (
    configure_logger,
    construct_auth_url,
    handle_api_response,
    make_default_session_headers,
    unix_seconds_to_datetime,
    validate_redirect_url,
)

logger.remove()  # remove default console logger


class SaxoOpenAPIClient:
    """Saxo OpenAPI Client.

    This class provides the main interface to interact with Saxo OpenAPI.

    An application config object file is required to initialize this class.
    """

    def __init__(
        self,
        app_config: Union[dict, str, None] = "app_config.json",
        log_sink: str = None,
        log_level: str = "DEBUG",
    ):
        """Create a new instance of SaxoOpenAPIClient.

        `app_config` should be a dictionary containing app config from Developer Portal
        or a path to a config file (defaults to `app_config.json` in local directory).

        Set `log_sink` and `log_level` to adjust logging output (useful if errors are
        encountered). Default: no logs are written, log level is `DEBUG` if sink is
        provided.
        """
        if log_sink:
            configure_logger(log_sink, log_level)

        self.client_session_id: str = token_urlsafe(10)
        logger.debug(
            f"initializing OpenAPI Client with session id: {self.client_session_id}"
        )

        self._app_config: OpenAPIAppConfig

        if isinstance(app_config, dict):
            self._app_config = parse_obj_as(OpenAPIAppConfig, app_config)
        elif isinstance(app_config, str):
            with open(app_config, "r") as f:
                config = json.load(f)
            self._app_config = parse_obj_as(OpenAPIAppConfig, config)
        else:
            raise RuntimeError(
                f"invalid type provided for 'app_config': {type(app_config)}"
            )
        self._http_client: Client = Client(
            headers=make_default_session_headers(),
            base_url=self._app_config.api_base_url,
        )
        self._token_data: Union[TokenData, None] = None
        self.streaming_context_id: Union[str, None] = None
        self.streaming_connection: Any = None
        logger.success("successfully parsed app config and initialized OpenAPI Client")

    def login(
        self,
        redirect_url: Optional[AnyHttpUrl] = None,
        launch_browser: bool = True,
        catch_redirect: bool = True,
        start_async_refresh: bool = False,
    ) -> None:
        """Log in to Saxo OpenAPI using the provided config provided in __init__().

        Defaults to first `localhost` in config (if not provided).

        - Use `launch_browser` to automatically show login page.
        - Use `catch_redirect` to start a server that will listen for the post-login
        redirect from Saxo SSO.
        - Use `start_async_refresh` to ensure the session is automatically refreshed (to
        be used in Jupyter Notebooks).
        """
        logger.debug(
            f"initializing login sequence with {redirect_url=}, {launch_browser=} "
            f"{catch_redirect=} {start_async_refresh=}"
        )
        _redirect_url = validate_redirect_url(self._app_config, redirect_url)
        state = token_urlsafe(20)
        auth_url = construct_auth_url(self._app_config, _redirect_url, state)
        logger.debug(f"logging in with {str(_redirect_url)=} and {str(auth_url)=}")

        if catch_redirect:
            redirect_server = RedirectServer(_redirect_url, state=state)
            redirect_server.start()

        if launch_browser:
            logger.debug("launching browser with login page")
            print(
                "🌐 opening login page in browser - waiting for user to "
                "authenticate... 🔑"
            )
            webbrowser.open_new(auth_url)
        else:
            print(f"🌐 navigate to the following web page to log in: {auth_url}")

        if catch_redirect:
            try:
                while not redirect_server.auth_code:
                    sleep(0.1)
                print("📞 received callback from Saxo SSO")
                _auth_code = parse_obj_as(AuthorizationCode, redirect_server.auth_code)
            except KeyboardInterrupt:
                print("🛑 operation interrupted by user - shutting down")
                return
            finally:
                redirect_server.shutdown()
        else:
            parsed_qs = None
            while not parsed_qs:
                try:
                    redirect_location_input = input("📎 paste redirect location (url): ")
                    redirect_location = parse_obj_as(
                        AnyHttpUrl, redirect_location_input
                    )
                    parsed_qs = parse_qs(redirect_location.query)
                    _auth_code = parse_obj_as(AuthorizationCode, parsed_qs["code"][0])
                except ValidationError as e:
                    print(f"❌ failed to parse provided url due to error(s): {e}")
                except KeyboardInterrupt:
                    print("🛑 operation interrupted by user - shutting down")
                    return

        self.get_tokens(auth_code=_auth_code)

        assert self._token_data

        env = self._app_config.env.value  # type: ignore[union-attr]
        perm = "WRITE / TRADE" if self._token_data.write_permission else "READ"

        print(
            f"✅ authorization succeeded - connected to {env} environment with "
            f"{perm} permissions (session ID {self._token_data.session_id})"
        )

        if (
            self._app_config.env is APIEnvironment.LIVE
            and self._token_data.write_permission
        ):
            print(
                "❗ NOTE: you are now connected to a real-money client in the LIVE "
                "environment with WRITE & TRADE permissions - this means that this "
                "client can create and change orders on your Saxo account!"
            )

        if start_async_refresh:
            asyncio.create_task(self.async_refresh(), name="async_refresh")

        logger.success("login completed successfully")

    def logout(self) -> None:
        """Disconnect by resetting session and deleting tokens and refresh thread."""
        assert self.logged_in
        logger.debug("disconnecting from OpenAPI")
        self._http_client = Client(
            headers=make_default_session_headers(),
            base_url=self._app_config.api_base_url,
        )
        self._token_data = None
        self.streaming_context_id = None
        self.streaming_connection = None
        refresh_thread = [
            thread for thread in threading.enumerate() if thread.name == "RefreshThread"
        ]
        if len(refresh_thread) > 0 and refresh_thread[0].is_alive():
            refresh_thread[0].cancel()  # type: ignore[attr-defined]
        logger.success("logout completed")

    def refresh(self) -> None:
        """Exercise refresh token and re-authorize streaming connection (if available).

        Automatically updates htt_session headers with new token and sends PUT request
        for the streaming websocket connection (if available).
        """
        logger.debug("refreshing API session")
        assert self.logged_in

        self.get_tokens()
        assert self._token_data

        if self.streaming_connection:
            logger.debug(
                "found streaming connection with context_id: "
                f"{self.streaming_context_id} - re-authorizing"
            )
            self.put(
                "/streamingws/authorize",
                params={"ContextId": self.streaming_context_id},
                data=None,
            )

        logger.debug("successfully refreshed API session")

    async def async_refresh(self) -> None:
        """Refresh the session automatically in an async loop."""
        while self.logged_in:
            delay = self.time_to_expiry - 30
            logger.debug(
                f"async refresh will kick off refresh flow in {delay} seconds at: "
                f"{unix_seconds_to_datetime(int(time()) + delay)}"
            )
            await asyncio.sleep(delay)
            logger.debug("async refresh delay has passed - kicking off refresh")
            self.refresh()
        logger.debug("async refresh stopped as the client is no longer logged in")

    def get_tokens(self, auth_code: AuthorizationCode = None) -> None:
        """Retrieve a new token pair by exercising a refresh token or auth code."""
        authorization_param = "code" if auth_code else "refresh_token"
        grant_type = "authorization_code" if auth_code else "refresh_token"
        logger.debug(f"exercising authorization with grant type: {grant_type}")

        token_request_params = {
            "grant_type": grant_type,
            authorization_param: auth_code
            or self._token_data.refresh_token,  # type: ignore[union-attr]
            "client_id": self._app_config.client_id,
            "client_secret": self._app_config.client_secret,
        }
        response = post(
            self._app_config.token_endpoint,
            params=token_request_params,
            headers={
                "user-agent": "saxo-apy/0.1.15",
            },
        )

        if response.status_code != 201:
            raise RuntimeError(
                "unexpected error occurred while retrieving token - response status: "
                f"{response.status_code}"
            )
        logger.success(
            "successfully exercised authorization - new token data retrieved"
        )

        received_token_data = response.json()
        self._token_data = TokenData.parse_obj(received_token_data)

    def setup_streaming_connection(self) -> None:
        """Configure a streaming websocket connection.

        This connection is used to receive messages from the OpenAPI Streaming Service.
        """
        assert self.logged_in

        if self.streaming_connection:
            raise RuntimeError("streaming connection already created")

        self.streaming_context_id = token_urlsafe(10)
        url = (
            f"{self._app_config.streaming_url}/connect?contextId="
            f"{self.streaming_context_id}"
        )
        headers = {
            "Authorization": "Bearer "
            f"{self._token_data.access_token}"  # type: ignore[union-attr]
        }
        self.streaming_connection = ws_client.connect(  # type: ignore[attr-defined]
            url, extra_headers=headers
        )

    def get(self, path: str, params: Optional[Dict] = None) -> dict:
        """Send GET request to OpenAPI and handle response."""
        response = handle_api_response(self.openapi_request("GET", path, params))
        return response.json()

    def post(self, path: str, data: dict, params: Optional[Dict] = None) -> dict:
        """Send POST request to OpenAPI and handle response."""
        response = handle_api_response(self.openapi_request("POST", path, params, data))
        return response.json()

    def put(
        self, path: str, data: Optional[dict], params: Optional[Dict] = None
    ) -> None:
        """Send PUT request to OpenAPI and handle response."""
        # always returns 202 Accepted or 204 No Content
        handle_api_response(self.openapi_request("PUT", path, params, data))

    def patch(
        self, path: str, data: dict, params: Optional[Dict] = None
    ) -> Optional[dict]:
        """Send PATCH request to OpenAPI and handle response."""
        response = handle_api_response(
            self.openapi_request("PATCH", path, params, data)
        )
        # may or may not return content based on endpoint
        if (
            response.headers.get("Content-Length")
            and int(response.headers["Content-Length"]) > 0
        ):
            return response.json()
        else:
            return None

    def delete(self, path: str, params: Optional[Dict] = None) -> None:
        """Send DELETE request to OpenAPI and handle response."""
        # always returns 204 No Content
        handle_api_response(self.openapi_request("DELETE", path, params))

    def openapi_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> Response:
        """Send a request to OpenAPI without additional handling of the response."""
        assert self.logged_in
        assert self._token_data

        if not path.startswith("/"):
            raise APIRequestError(
                "requested path does not start with '/' and won't be able to be "
                f"resolved by OpenAPI: {path}"
            )

        headers = {
            "x-request-id": (f"saxo-apy/{self.client_session_id}/{token_urlsafe(20)}"),
            "authorization": f"Bearer {self._token_data.access_token}",
        }

        logger.debug(
            f"performing request: {method} {self.api_base_url}{path}, "
            f"{params=}, {data=}"
        )

        response = self._http_client.request(
            method,
            path,
            params=params,
            json=data,
            headers=headers,
        )

        logger.debug(
            f"response received with status: {response.status_code}, X-Correlation: "
            f"{response.headers.get('X-Correlation')}"
        )

        return response

    @property
    def available_redirect_urls(self) -> List[AnyHttpUrl]:
        """Retrieve available redirect URLs for login from app config."""
        return self._app_config.redirect_urls

    @property
    def api_base_url(self) -> HttpsUrl:
        """Retrieve base URL to construct requests with."""
        return self._app_config.api_base_url

    @property
    def streaming_url(self) -> HttpsUrl:
        """Retrieve streaming URL to set up websocket connection."""
        return self._app_config.streaming_url  # type: ignore[return-value]

    @property
    def logged_in(self) -> bool:
        """Check if the client is connected with a valid session to OpenAPI.

        If no token data is available, the client is not logged in (yet).
        If the access token has expired, the client is effectively disconnected.
        """
        if not self._token_data:
            raise NotLoggedInError(
                "no active session found - connect the client with '.login()'"
            )
        if time() > self._token_data.access_token_expiry:
            raise TokenExpiredError(
                "access token has expired - reconnect the client with '.login()'"
            )
        return True

    @property
    def access_token_expiry(self) -> datetime:
        """Retrieve human-readable access token expiry."""
        assert self.logged_in
        return unix_seconds_to_datetime(
            self._token_data.access_token_expiry  # type: ignore[union-attr]
        )

    @property
    def time_to_expiry(self) -> int:
        """Retrieve time in seconds until access token expires."""
        assert self.logged_in
        token_expiry = self._token_data.access_token_expiry  # type: ignore[union-attr]
        return token_expiry - int(time())
