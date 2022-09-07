import threading
import webbrowser
from datetime import datetime
from secrets import token_urlsafe
from time import sleep, time
from typing import Dict, List, Optional, Union
from urllib.parse import parse_qs

from loguru import logger
from pydantic import AnyHttpUrl, ValidationError, parse_obj_as
from requests import Response, Session

from .models import (
    APIEnvironment,
    APIRequestError,
    AuthorizationCode,
    AuthorizationType,
    HttpsUrl,
    NotLoggedInError,
    OpenAPIAppConfig,
    TokenData,
    TokenExpiredError,
)
from .redirect_server import RedirectServer
from .utils import (
    construct_auth_url,
    exercise_authorization,
    handle_api_response,
    make_default_session_headers,
    unix_seconds_to_datetime,
    validate_redirect_url,
)

logger.remove()


class SaxoOpenAPIClient:
    """Saxo OpenAPI Client.

    This class provides the main interface to interact with Saxo OpenAPI.

    An application config object file is required to initialize this class.
    """

    @logger.catch(reraise=True)
    def __init__(
        self, app_config: dict, log_sink: str = None, log_level: str = "DEBUG"
    ):
        if log_sink:
            logger.add(
                log_sink,
                format=(
                    "{time:!UTC} {thread:12} {module:15} {line:3} {level:8} {message}"
                ),
                level=log_level,
                enqueue=True,
            )

        self.client_session_id: str = token_urlsafe(10)
        logger.debug(f"initializing OpenAPI Client with {self.client_session_id=}")

        self._app_config: OpenAPIAppConfig = parse_obj_as(OpenAPIAppConfig, app_config)
        self._http_session: Session = Session()
        self._http_session.headers = make_default_session_headers()
        self._token_data: Union[TokenData, None] = None
        logger.success("successfully parsed app config and initialized OpenAPI Client")

    @logger.catch(reraise=True)
    def login(
        self,
        redirect_url: Optional[AnyHttpUrl] = None,
        with_browser: bool = True,
        with_server: bool = True,
        auto_refresh: bool = False,
    ) -> None:
        logger.debug("initializing login sequence")
        _redirect_url = validate_redirect_url(self._app_config, redirect_url)
        state = token_urlsafe(20)
        auth_url = construct_auth_url(self._app_config, _redirect_url, state)
        logger.debug(f"logging in with {str(_redirect_url)=} and {str(auth_url)=}")

        if with_server:
            redirect_server = RedirectServer(_redirect_url, state=state)
            redirect_server.start()

        if with_browser:
            logger.debug("launching browser with login page")
            print(
                "🌐 opening login page in browser - waiting for user to "
                "authenticate... 🔑"
            )
            webbrowser.open_new(auth_url)
        else:
            print(f"🌐 navigate to the following web page to log in: {auth_url}")

        if with_server:
            try:
                while not redirect_server.auth_code:
                    sleep(0.1)
                print("📞 received callback from Saxo SSO")
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
                except ValidationError as e:
                    print(f"❌ failed to parse provided url due to error(s): {e}")
                except KeyboardInterrupt:
                    print("🛑 operation interrupted by user - shutting down")
                    return

        token_data = exercise_authorization(
            app_config=self._app_config,
            authorization=parse_obj_as(AuthorizationCode, redirect_server.auth_code),
            type=AuthorizationType.CODE,
            redirect_url=_redirect_url,
        )

        self._http_session.headers.update(
            {"authorization": f"Bearer {token_data.access_token}"}
        )
        self._token_data = token_data

        assert self._app_config.env
        env_msg = "🛠 SIM" if self._app_config.env is APIEnvironment.SIM else "🎉 LIVE"
        perm = "🔧 write / 📈 trade" if self._token_data.write_permission else "👀 read"

        print(
            f"✅ authorization succeeded - connected to {env_msg} environment with "
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

        if auto_refresh:
            self.start_auto_refresh()

        logger.success("login completed successfully")

    def refresh(self) -> None:
        assert self.logged_in
        refreshed_token_data = exercise_authorization(
            app_config=self._app_config,
            authorization=self._token_data.refresh_token,  # type: ignore[union-attr]
            type=AuthorizationType.REFRESH_TOKEN,
            redirect_url=self._token_data.redirect_url,  # type: ignore[union-attr]
        )
        self._http_session.headers.update(
            {"authorization": f"Bearer {refreshed_token_data.access_token}"}
        )
        self._token_data = refreshed_token_data

    def start_auto_refresh(self) -> None:
        def refresh_loop() -> None:
            logger.debug(
                f"access token valid until: {self.access_token_expiry}, "
                f"which is {self.time_to_expiry} seconds from now"
            )

            if self.time_to_expiry < 60:
                logger.debug("time to expiry less than 1 minute - kicking off refresh")
                self.refresh()

            logger.debug(
                f"access token valid until: {self.access_token_expiry}, "
                f"which is {self.time_to_expiry} seconds from now"
            )

            delay_time = self.time_to_expiry - 30
            logger.debug(
                f"setting delay for next refresh in {delay_time} seconds, at: "
                f"{unix_seconds_to_datetime(int(time())+delay_time)}"
            )

            refresh_thread = threading.Timer(delay_time, refresh_loop)
            refresh_thread.name = "RefreshThread"
            refresh_thread.start()
            logger.success(f"refresh thread started with id: {refresh_thread.ident}")

        refresh_loop()

    @logger.catch(reraise=True)
    def get(self, path: str, params: Optional[Dict] = None) -> dict:
        response = handle_api_response(self.openapi_request("GET", path, params))
        return response.json()

    @logger.catch(reraise=True)
    def post(self, path: str, data: dict, params: Optional[Dict] = None) -> dict:
        response = handle_api_response(self.openapi_request("POST", path, params, data))
        return response.json()

    @logger.catch(reraise=True)
    def put(self, path: str, data: dict, params: Optional[Dict] = None) -> None:
        # always returns 204 No Content
        handle_api_response(self.openapi_request("PUT", path, params, data))

    @logger.catch(reraise=True)
    def patch(
        self, path: str, data: dict, params: Optional[Dict] = None
    ) -> Optional[dict]:
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

    @logger.catch(reraise=True)
    def delete(self, path: str, params: Optional[Dict] = None) -> None:
        # always returns 204 No Content
        handle_api_response(self.openapi_request("DELETE", path, params))

    def openapi_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> Response:
        assert self.logged_in

        if not path.startswith("/"):
            raise APIRequestError(
                "requested path does not start with '/' and won't be able to be "
                f"resolved by OpenAPI: {path}"
            )

        with self._http_session as session:
            return session.request(
                method,
                f"{self.api_base_url}{path}",
                params=params,
                json=data,
                headers={
                    "x-request-id": (
                        f"saxo-apy/{self.client_session_id}/{token_urlsafe(20)}"
                    ),
                },
            )

    @property
    def available_redirect_urls(self) -> List[AnyHttpUrl]:
        """Convenience function to select available redirect URLs for login."""
        return self._app_config.redirect_urls

    @property
    def api_base_url(self) -> HttpsUrl:
        """Used by .openapi_request() to construct request URL."""
        return self._app_config.api_base_url

    @property
    def streaming_url(self) -> HttpsUrl:
        return self._app_config.streaming_url  # type: ignore[return-value]

    @property
    def logged_in(self) -> bool:
        """Checks if the client is connected with a valid session to OpenAPI.

        If no token data is available, the client is not logged in (yet).
        If the refresh token has expired, the client is effectively disconnected.
        A valid refresh token will always allow the client to exercise for a new
        access token and hence keep the session alive.
        """
        try:
            assert self._token_data
        except AssertionError:
            raise NotLoggedInError(
                "no active session found - connect your client with '.login()'"
            )
        if time() > self._token_data.refresh_token_expiry:
            raise TokenExpiredError(
                "refresh token has expired - reconnect your client with '.login()'"
            )
        return True

    @property
    def access_token_expiry(self) -> datetime:
        """Convenience function to check expiry of access token"""
        assert self.logged_in
        return unix_seconds_to_datetime(
            self._token_data.access_token_expiry  # type: ignore[union-attr]
        )

    @property
    def time_to_expiry(self) -> int:
        assert self.logged_in
        token_expiry = self._token_data.access_token_expiry  # type: ignore[union-attr]
        return token_expiry - int(time())

    @property
    def refresh_token_expiry(self) -> datetime:
        """Convenience function to check expiry of refresh token"""
        assert self.logged_in
        return unix_seconds_to_datetime(
            self._token_data.refresh_token_expiry  # type: ignore[union-attr]
        )
