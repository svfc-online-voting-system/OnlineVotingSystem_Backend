""" This module is used to run the Flask app. """

# pylint: disable=C0413

from os import getenv

from ssl import SSLContext, PROTOCOL_TLS_SERVER

from dotenv import load_dotenv, find_dotenv
from flask_cors import CORS
from werkzeug.serving import run_simple

load_dotenv(find_dotenv())

from app import create_app


def create_ssl_context():
    """This function creates an SSL context for the Flask app."""
    ssl_context = SSLContext(protocol=PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile="certs/localhost+1.pem", keyfile="certs/localhost+1-key.pem"
    )
    return ssl_context


ENVIRONMENT = getenv("ENVIRONMENT", "")

IS_PRODUCTION = ENVIRONMENT == "production"

app = create_app()
CORS(
    app,
    supports_credentials=True,
    origins=[getenv("LOCAL_FRONTEND_URL", ""), getenv("LIVE_FRONTEND_URL", "")],
)

configured_ssl_context = create_ssl_context()

if __name__ == "__main__":
    if IS_PRODUCTION:
        app.run(host="0.0.0.0", port=5000)
    else:
        run_simple(
            hostname="localhost",
            port=5000,
            application=app,
            threaded=True,
            ssl_context=configured_ssl_context,
            use_reloader=True,
            use_debugger=True,
            use_evalex=True,
        )
