from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
from pydantic import AnyHttpUrl, parse_obj_as
from pytest import MonkeyPatch, mark, raises

from saxo_apy.models import (
    AuthorizationCode,
    AuthorizationType,
    OpenAPIAppConfig,
    TokenData,
)
from saxo_apy.utils import (
    construct_auth_url,
    exercise_authorization,
    make_default_session_headers,
    unix_seconds_to_datetime,
    validate_redirect_url,
)

from .fixtures.models import DUMMY_LIVE_CONFIG, DUMMY_SIM_CONFIG, MockAuthResponse


def test_make_default_session_headers() -> None:
    headers = make_default_session_headers()

    expected_headers = {
        "accept-encoding": "gzip",
        "user-agent": "saxo-apy/0.1.10",
        "connection": "keep-alive",
        "cache-control": "no-cache",
        "accept": "application/json; charset=utf-8",
    }
    for header, value in headers.items():
        assert value == expected_headers[header]


@mark.parametrize(
    "unix, datetime",
    [
        (1, datetime(1970, 1, 1, 0, 0, 1, tzinfo=timezone.utc)),
        (2, datetime(1970, 1, 1, 0, 0, 2, tzinfo=timezone.utc)),
        (2657175467, datetime(2054, 3, 15, 8, 17, 47, tzinfo=timezone.utc)),
    ],
)
def test_unix_seconds_to_datetime(unix: int, datetime: datetime) -> None:
    assert datetime == unix_seconds_to_datetime(unix)


def test_validate_redirect_url() -> None:
    config = parse_obj_as(OpenAPIAppConfig, DUMMY_SIM_CONFIG)

    # test default to first localhost if None provided
    assert "http://localhost:12321/redirect1" == validate_redirect_url(config, None)

    # test selecting a valid redirect_url from config
    assert "http://example.net:12321/redirect" == validate_redirect_url(
        config, config.redirect_urls[2]
    )

    # test selecting invalid redirect_url
    with raises(AssertionError, match="not available in app config"):
        validate_redirect_url(
            config,
            parse_obj_as(AnyHttpUrl, "http://example.net:12321/invalid-redirect"),
        )


@mark.parametrize(
    "config",
    [
        (DUMMY_SIM_CONFIG),
        (DUMMY_LIVE_CONFIG),
    ],
)
def test_construct_auth_url(config: dict) -> None:
    _config = parse_obj_as(OpenAPIAppConfig, config)
    auth_url = construct_auth_url(_config, _config.redirect_urls[0], "state123")
    querystring = parse_qs(auth_url.query)
    assert querystring["response_type"][0] == _config.grant_type.value.lower()
    assert querystring["client_id"][0] == _config.client_id
    assert querystring["state"][0] == "state123"
    assert querystring["redirect_uri"][0] == _config.redirect_urls[0]


@mark.parametrize(
    "auth_type",
    [
        (AuthorizationType.CODE),
        (AuthorizationType.REFRESH_TOKEN),
    ],
)
def test_exercise_authorization(
    auth_type: AuthorizationType, monkeypatch: MonkeyPatch
) -> None:
    config = parse_obj_as(OpenAPIAppConfig, DUMMY_SIM_CONFIG)
    auth_token = parse_obj_as(AuthorizationCode, "11111111-1111-1111-1111-111111111111")

    def mock_auth(url: str, params: dict) -> MockAuthResponse:
        return MockAuthResponse()

    monkeypatch.setattr(httpx, "post", mock_auth)

    token_data = exercise_authorization(
        config, auth_type, auth_token, redirect_url=config.redirect_urls[0]
    )

    assert isinstance(token_data, TokenData)

    monkeypatch.setattr(MockAuthResponse, "status_code", 401)

    with raises(RuntimeError, match="unexpected error occurred while retrieving token"):
        token_data = exercise_authorization(
            config, auth_type, auth_token, redirect_url=config.redirect_urls[0]
        )
