# Saxo-APY: Python Client for Saxo Bank OpenAPI

*A lightweight Python client for hassle-free tinkering with Saxo OpenAPI.*

[![python](https://img.shields.io/badge/python-3.7+-blue)](https://github.com/SaxoBank/saxo-openapi-client-python)

> NOTE: This piece of software was created by an enthusiast as a learning project. None of the contents in this repository are maintained by Saxo Bank, and Saxo Bank does not guarantee correctness of the provided implementation.


## Features

- [x] Authentication and session management with Saxo SSO OAuth 2.0
    - Supports OAuth `Code` grant type
    - Works seamlessly in both `SIM` and `LIVE` environments (with read and write/trade permissions)
    - Automated handling of callback (optional)
    - Headless authentication for deployed applications (optional)
    - Keep session active by refreshing access tokens:
        - Via a separate thread (useful for Jupyter Notebooks)
        - Via an async function that can be used while streaming
- [x] Read operations (`GET` requests)
- [x] Write operations (`POST`, `PUT`, `PATCH`, `DELETE`, requests)
- [x] Supports streaming and decoding of streaming messages
- [x] Error handling with practical exception messages


## Installation

`pip install saxo-apy`


## Requirements

- Python 3.7+
- An OpenAPI application registered [on Saxo Bank's Developer Portal](https://www.developer.saxo/openapi/appmanagement)
    - [Create a free developer account](https://www.developer.saxo/accounts/sim/signup) if you don't have one already.
    - Ensure the application is set up with `Grant Type: Code` as authentication flow.
    - At least 1 localhost redirect needs to be defined such as `http://localhost:12321/redirect` (for development/testing purposes)
    - (Optional) enable trading permissions for the app


## Usage

> See [Get Started](/samples/01_get_started.ipynb) for an in-depth example!

Copy your apps's config by clicking `Copy App Object` on the Developer Portal app details page.

The client requires this dictionary to be provided when initializing:

```Python
from saxo_apy import SaxoOpenAPIClient

# copy app config here:
config = {
    "AppName": "Your OpenAPI App",
    "AppKey": "...",
    "AuthorizationEndpoint": "...",
    "TokenEndpoint": "...",
    "GrantType": "Code",
    "OpenApiBaseUrl": "...",
    "RedirectUrls": [
        "...
    ],
    "AppSecret": "..."
}

client = SaxoOpenAPIClient(config)
```

See [the samples](/samples/README.md) for loads more examples on how to use the client.


## Dependencies

This package requires 4 dependencies:

- `pydantic`, for parsing config and JSON responses 
- `Flask`, to run a local server and catch the callback from Saxo SSO
- `httpx`, for sending requests to OpenAPI and managing the client session
- `PyJWT`, for parsing and validating access tokens
- `loguru`, to handle logging


## Notes

The client supports OAuth Code flow and will automatically spin up a server to listen for the redirect from Saxo SSO. At least 1 `localhost` redirect needs to be defined in application config for this purpose.

By default, the client will use the _first available localhost redirect_ to run the server on (typically only 1 exists in the config).

The client validates redirect urls in application config automatically. OAuth 2.0 code flow requires a fixed port to be specified on the redirect url. In case this is incorrectly configured, an error message will guide you to ensure app config is correct with OpenAPI:

```
one or more redirect urls have no port configured, which is required for grant type 'Code' - ensure a port is configured in the app config object for each url (example: http://localhost:23432/redirect)
```
