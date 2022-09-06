from enum import Enum
from re import compile
from time import time
from typing import List, Optional

from jwt import decode
from pydantic import (
    AnyHttpUrl,
    AnyUrl,
    BaseConfig,
    BaseModel,
    ConstrainedStr,
    Extra,
    Field,
    root_validator,
)

SIM_STREAMING_URL = "https://streaming.saxobank.com/sim/openapi/streamingws/"
LIVE_STREAMING_URL = "https://streaming.saxobank.com/openapi/streamingws/"


class ClientId(ConstrainedStr):
    regex = compile(r"^[a-f0-9]{32}$")


class ClientSecret(ClientId):
    pass


class HttpsUrl(AnyUrl):
    allowed_schemes = {"https"}


class GrantType(Enum):
    CODE = "Code"


class APIEnvironment(Enum):
    SIM = "SIM"
    LIVE = "LIVE"


class AuthorizationCode(ConstrainedStr):
    regex = compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")


class RefreshToken(AuthorizationCode):
    pass


class AuthorizationType(Enum):
    CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"


class OpenAPIAppConfig(BaseModel):
    """Dataclass for parsing and validating app config objects."""

    app_name: str = Field(..., alias="AppName")
    grant_type: GrantType = Field(..., alias="GrantType")
    client_id: ClientId = Field(..., alias="AppKey")
    client_secret: ClientSecret = Field(..., alias="AppSecret")
    auth_endpoint: HttpsUrl = Field(..., alias="AuthorizationEndpoint")
    token_endpoint: HttpsUrl = Field(..., alias="TokenEndpoint")
    api_base_url: HttpsUrl = Field(..., alias="OpenApiBaseUrl")
    streaming_url: Optional[HttpsUrl]
    redirect_urls: List[AnyHttpUrl] = Field(..., alias="RedirectUrls")
    env: Optional[APIEnvironment]

    @root_validator
    def validate_redirect_urls_contains_localhost(cls, values: dict) -> dict:
        available_hosts = [url.host for url in values["redirect_urls"]]
        assert "localhost" in available_hosts, (
            "at least 1 'localhost' redirect URL required in app config - "
            f"hosts: {available_hosts}"
        )
        return values

    @root_validator
    def validate_port_configuration_redirect_urls(cls, values: dict) -> dict:
        assert all([url.port for url in values["redirect_urls"]]), (
            "one or more redirect URLs have no port configured, which is required "
            "for grant type 'Code' - ensure a port is configured in the app config "
            "object for each URL (example: http://localhost:23432/redirect) - "
            f"URLs: {[str(url) for url in values['redirect_urls']]}"
        )
        return values

    @root_validator
    def strip_base_url_suffix(cls, values: dict) -> dict:
        values["api_base_url"] = values["api_base_url"].rstrip("/")
        return values

    @root_validator
    def derive_env_fields(cls, values: dict) -> dict:
        if "sim.logonvalidation" in values["auth_endpoint"]:
            values["env"] = APIEnvironment.SIM
            values["streaming_url"] = SIM_STREAMING_URL
        if "live.logonvalidation" in values["auth_endpoint"]:
            values["env"] = APIEnvironment.LIVE
            values["streaming_url"] = LIVE_STREAMING_URL
        return values

    class Config(BaseConfig):
        extra = Extra.forbid


class TokenData(BaseModel):
    """Dataclass for parsing token data."""

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: RefreshToken
    refresh_token_expires_in: int
    base_uri: Optional[HttpsUrl]
    redirect_url: AnyHttpUrl
    access_token_expiry: int
    refresh_token_expiry: int
    client_key: str
    user_key: str
    session_id: str
    write_permission: bool

    @root_validator(pre=True)
    def set_fields_from_token_payload(cls, values: dict) -> dict:
        payload = decode(
            values["access_token"],
            options={
                "verify_signature": False,  # signature not verified
            },
        )

        values["access_token_expiry"] = payload["exp"]
        values["refresh_token_expiry"] = (
            int(time()) + values["refresh_token_expires_in"]
        )
        values["client_key"] = payload["cid"]
        values["user_key"] = payload["uid"]
        values["session_id"] = payload["sid"]
        values["write_permission"] = True if payload["oaa"] == "77770" else False

        return values


class NotLoggedInError(Exception):
    pass


class TokenExpiredError(Exception):
    pass


class APIRequestError(Exception):
    pass


class APIResponseError(Exception):
    pass
