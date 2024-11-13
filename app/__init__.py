"""
Factory function to create the Flask app instance.

	- Creates a Flask app instance.
	- Configures JWTManager for the app.
	- Sets up logging for the app.
	- Registers the blueprints.

Returns:
	Flask: The Flask app instance.
"""

from os import path

from flask import Flask
from flask_jwt_extended import (
    JWTManager,
)

from app.blueprints import register_blueprints
from app.config.development import DevelopmentConfig
from app.extension import mail
from app.utils.error_handlers.system_wide_error_handler import (
    register_system_wide_errors,
)
from app.utils.jwt_helpers import add_jwt_after_request_handler
from app.utils.logger import setup_logging


def create_app():
    """Factory function to create the Flask app instance."""
    base_dir = path.abspath(path.dirname(__file__))
    template_dir = path.join(base_dir, "templates")

    app = Flask(__name__, template_folder=template_dir)
    app.config.from_object(DevelopmentConfig)

    JWTManager(app)
    mail.init_app(app)

    setup_logging(app)
    register_blueprints(app)
    register_system_wide_errors(app)
    add_jwt_after_request_handler(app)
    return app
