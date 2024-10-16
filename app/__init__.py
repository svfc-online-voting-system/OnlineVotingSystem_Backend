"""
Factory function to create the Flask app instance.

	- Creates a Flask app instance.
	- Configures JWTManager for the app.
	- Sets up logging for the app.
	- Registers the auth blueprint.

Returns:
	Flask: The Flask app instance.
"""


# app/__init__.py
import logging
import os
from flask import Flask
from flask_jwt_extended import JWTManager
from app.extension import mail, csrf
from app.routes.auth import auth_blueprint


def create_app():
    """Factory function to create the Flask app instance."""
    app = Flask(__name__, template_folder='templates')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default-secret-key')
    app.config['JWT_ACCESS_COOKIE_NAME'] = 'Authorization'
    app.config['CSRF_HEADER_NAME'] = 'X-CSRF-TOKEN'
    app.config['CSRF_COOKIE_HTTPONLY'] = True
    app.config['CSRF_COOKIE_SECURE'] = True
    app.config['CSRF_COOKIE_SAMESITE'] = 'None'
    app.config['CSRF_COOKIE_NAME'] = 'X-CSRF-TOKEN'
    csrf.init_app(app)
    JWTManager(app)
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    mail.init_app(app)
    os.makedirs(os.path.join(app.root_path, 'logs'), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(app.root_path, 'logs', 'authentication.log')),
            logging.StreamHandler()
        ]
    )
    app.register_blueprint(auth_blueprint)
    logging.getLogger()
    return app
