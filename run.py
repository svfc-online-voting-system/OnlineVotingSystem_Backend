""" This module is used to run the Flask app. """

# pylint: disable=C0413, W0621

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


configured_ssl_context = create_ssl_context()

ENVIRONMENT = getenv("ENVIRONMENT", "")

IS_PRODUCTION = ENVIRONMENT == "production"


def create_app_with_cors():
    """Creates Flask app with proper CORS configuration"""
    app = create_app()

    allowed_origins = ["https://localhost:4200", getenv("LIVE_FRONTEND_URL", "")]

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": allowed_origins,
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
                "allow_headers": [
                    "Content-Type",
                    "Authorization",
                    "Access-Control-Allow-Credentials",
                    "X-CSRF-TOKEN",
                    "Access-Control-Allow-Origin",
                    "csrf-refresh-token",
                    "refresh_token_cookie",
                ],
                "supports_credentials": True,
                "expose_headers": ["Content-Range", "X-Content-Range"],
            }
        },
    )
    return app


app = create_app_with_cors()

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
