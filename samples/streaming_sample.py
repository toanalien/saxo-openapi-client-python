"""Simple streaming websocket example printing EURUSD prices to the terminal."""

import asyncio
from pprint import pprint

from saxo_apy import SaxoOpenAPIClient
from saxo_apy.utils import decode_streaming_message

client = SaxoOpenAPIClient()
client.login()  # ensure app_config.json is available in this directory


async def create_subscription() -> None:
    """Create subscription for EURUSD prices."""
    sub = client.post(
        "/trade/v1/prices/subscriptions",
        data={
            "Arguments": {
                "Uic": 21,
                "AssetType": "fxspot",
            },
            # this value is set when the streaming connection is initialised
            "ContextId": client.streaming_context_id,
            "ReferenceId": "eurusd",
            "RefreshRate": 500,
        },
    )
    pprint(sub)


async def message_handler() -> None:
    """Handle each received message by printing it to the terminal."""
    async with client.streaming_connection as stream:
        async for message in stream:
            decoded = decode_streaming_message(message)
            print(decoded)


async def main() -> None:
    """Execute main application logic."""
    client.setup_streaming_connection()
    # ensure refresh is called and websocket is re-authorized
    asyncio.ensure_future(client.async_refresh())
    await create_subscription()

    # this call will run forever, receiving messages until interrupted by user
    await message_handler()


# run the app
asyncio.run(main())
