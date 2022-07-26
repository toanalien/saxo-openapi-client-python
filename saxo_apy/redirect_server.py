import logging
import threading

from flask import Flask, request
from pydantic import AnyHttpUrl
from werkzeug.serving import make_server


class RedirectServer(threading.Thread):
    """Simple redirect server to catch callback from Saxo SSO.

    A custom str value 'callback_url' is created on the server app object to indicate
    whether a callback has been received.
    """

    def __init__(self, redirect_url: AnyHttpUrl):

        app = Flask(__name__)
        self.callback_url = None

        assert redirect_url.path

        @app.route(redirect_url.path)
        def handle_redirect() -> str:
            self.callback_url = request.url
            if "error" not in request.url:
                display_text = "✅ Login succeeded! Please return to the application."
            else:
                display_text = (
                    "🚫 It looks like an error occurred - check the application for "
                    "details."
                )
            return f"""
<center><h2 style='font-family: sans-serif;'>
{display_text}
</h2></center>
"""

        threading.Thread.__init__(self)
        host = "0.0.0.0"  # for local redirect or deployed instance
        port = redirect_url.port

        assert port
        self.server = make_server(host, int(port), app)
        self.ctx = app.app_context()
        self.ctx.push()
        logging.getLogger(
            "werkzeug"
        ).disabled = True  # disable server logging to stdout

    def run(self) -> None:
        self.server.serve_forever()

    def shutdown(self) -> None:
        self.server.shutdown()
