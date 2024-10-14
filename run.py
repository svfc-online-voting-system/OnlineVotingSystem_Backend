""" This module is used to run the Flask app. """
from os import getenv
from ssl import SSLContext, PROTOCOL_TLS_SERVER
from dotenv import load_dotenv
from flask_cors import CORS
from werkzeug.serving import run_simple
from app import create_app

load_dotenv()

def create_ssl_context():
    """ This function creates an SSL context for the Flask app. """
    ssl_context = SSLContext(protocol=PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile='certs/localhost+1.pem',
        keyfile='certs/localhost+1-key.pem'
    )
    return ssl_context

app = create_app()
CORS(app, supports_credentials=True, origins=[getenv('LOCAL_FRONTEND_URL'), getenv('LIVE_FRONTEND_URL')])

configured_ssl_context = create_ssl_context()

if __name__ == '__main__':
    run_simple(
        'localhost',
        5000,
        app,
        ssl_context=configured_ssl_context,
        use_reloader=True,
        use_debugger=True
    )
