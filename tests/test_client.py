import time

from pydantic import ValidationError, parse_obj_as
from pytest import MonkeyPatch, mark, raises
from saxo_apy.client import SaxoOpenAPIClient
from saxo_apy.models import (
    LIVE_STREAMING_URL,
    SIM_STREAMING_URL,
    APIEnvironment,
    NotLoggedInError,
    OpenAPIAppConfig,
    TokenData,
    TokenExpiredError,
)

from .fixtures.models import DUMMY_ACCESS_TOKEN, DUMMY_LIVE_CONFIG, DUMMY_SIM_CONFIG

DUMMY_TOKEN_DATA = TokenData(
    access_token=DUMMY_ACCESS_TOKEN,
    token_type="Bearer",
    expires_in=1200,
    refresh_token="12341234-1234-1234-1234-123412341234",
    refresh_token_expires_in=3600,
    base_uri=None,
    redirect_url="https://localhost:12321/redirect",
)


@mark.parametrize(
    "config, env",
    [
        (DUMMY_SIM_CONFIG, APIEnvironment.SIM),
        (DUMMY_LIVE_CONFIG, APIEnvironment.LIVE),
    ],
)
def test_init_valid_config(config: dict, env: APIEnvironment) -> None:
    client = SaxoOpenAPIClient(app_config=config)

    assert isinstance(client._app_config, OpenAPIAppConfig)
    assert client._app_config == parse_obj_as(OpenAPIAppConfig, config)
    assert client._app_config.env is env
    assert not client._app_config.api_base_url.endswith("/")
    assert client.api_base_url == config["OpenApiBaseUrl"].rstrip("/")
    assert client.available_redirect_urls == config["RedirectUrls"]

    if env is APIEnvironment.SIM:
        assert client.streaming_url == SIM_STREAMING_URL
    if env is APIEnvironment.LIVE:
        assert client.streaming_url == LIVE_STREAMING_URL


@mark.parametrize(
    "redirect_url, exc_msg",
    [
        (
            "https://example.com:12321/redirect",
            "at least 1 'localhost'",
        ),
        (
            "https://localhost/redirect",
            "have no port configured",
        ),
    ],
)
def test_init_bad_redirect_url(
    redirect_url: str, exc_msg: str, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setitem(DUMMY_SIM_CONFIG, "RedirectUrls", [redirect_url])

    with raises(
        ValidationError,
        match=exc_msg,
    ):
        SaxoOpenAPIClient(app_config=DUMMY_SIM_CONFIG)


def test_logged_in(monkeypatch: MonkeyPatch) -> None:
    client = SaxoOpenAPIClient(app_config=DUMMY_SIM_CONFIG)

    # when initialized, the client is not logged in yet
    with raises(NotLoggedInError, match="no active session found"):
        client.logged_in

    # set fake access token with expiry in future - client should now be connected
    monkeypatch.setattr(client, "_token_data", DUMMY_TOKEN_DATA)
    assert client.logged_in

    # change expiry to value before current time() - client is now disconnected
    monkeypatch.setattr(client._token_data, "access_token_expiry", 1)
    with raises(TokenExpiredError, match="access token has expired"):
        client.logged_in


def test_token_expiries() -> None:
    client = SaxoOpenAPIClient(app_config=DUMMY_SIM_CONFIG)
    client._token_data = DUMMY_TOKEN_DATA

    assert client.access_token_expiry.timestamp() > time.time()
