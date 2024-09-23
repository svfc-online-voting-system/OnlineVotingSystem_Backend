"""
Factory function to create the Flask app instance.

	- Creates a Flask app instance.
	- Configures JWTManager for the app.
	- Sets up logging for the app.
	- Registers the auth blueprint.

Returns:
	Flask: The Flask app instance.
"""


import logging
import os
from flask import Flask
from flask_jwt_extended import JWTManager
from app.routes.auth import auth_blueprint


def create_app():
    """
            _factory function to create the Flask app instance_
    """

    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = os.getenv(
        'JWT_SECRET_KEY', 'default-secret-key')
    app.config['JWT_ACCESS_COOKIE_NAME'] = 'Authorization'

    JWTManager(app)

    os.makedirs(os.path.join(app.root_path, 'logs'), exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(
                app.root_path, 'logs', 'authentication.log')),
            logging.StreamHandler()
        ]
    )

    app.register_blueprint(auth_blueprint)

    logging.getLogger()

    return app
