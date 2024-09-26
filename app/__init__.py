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
from app.extension import mail
from app.routes.auth import auth_blueprint


def create_app():
    """Factory function to create the Flask app instance."""
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default-secret-key')
    app.config['JWT_ACCESS_COOKIE_NAME'] = 'Authorization'
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
