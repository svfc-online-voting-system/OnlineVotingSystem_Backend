"""
Factory function to create the Flask app instance.

	- Creates a Flask app instance.
	- Configures JWTManager for the app.
	- Sets up logging for the app.
	- Registers the auth blueprint.

Returns:
	Flask: The Flask app instance.
"""

from logging import FileHandler, StreamHandler, basicConfig, getLogger, INFO
from os import getenv, makedirs, path

from flask import Flask
from flask_jwt_extended import JWTManager
from flask_jwt_extended.exceptions import CSRFError
from marshmallow import ValidationError
from sqlalchemy.exc import IntegrityError, DataError, DatabaseError, OperationalError

from app.extension import mail
from app.routes.auth import auth_blueprint
from app.routes.poll import poll_blueprint
from app.utils.error_handlers.jwt_error_handlers import handle_csrf_error
from app.utils.error_handlers.database_error_handlers import handle_database_errors
from app.utils.error_handlers.validation_error_handler import handle_validation_errors
from app.utils.error_handlers.general_error_handler import (
    handle_general_exception,
    handle_type_error,
)


def create_app():
    """Factory function to create the Flask app instance."""
    base_dir = path.abspath(path.dirname(__file__))
    template_dir = path.join(base_dir, "templates")

    app = Flask(__name__, template_folder=template_dir)

    app.config["SECRET_KEY"] = getenv("SECRET_KEY")
    app.config["JWT_SECRET_KEY"] = getenv("JWT_SECRET_KEY")
    app.config["JWT_ALGORITHM"] = "HS256"
    app.config["JWT_DECODE_ALGORITHMS"] = ["HS256"]
    app.config["JWT_ACCESS_COOKIE_NAME"] = "Authorization"
    app.config["JWT_TOKEN_LOCATION"] = ["cookies", "headers"]
    app.config["JWT_HEADER_NAME"] = "Authorization"
    app.config["JWT_HEADER_TYPE"] = "Bearer"
    app.config["JWT_COOKIE_SECURE"] = True
    app.config["JWT_SESSION_COOKIE"] = True
    app.config["JWT_COOKIE_CSRF_PROTECT "] = True
    app.config["JWT_CSRF_CHECK_FORM"] = False
    app.config["JWT_CSRF_IN_COOKIES"] = True
    app.config["JWT_CSRF_METHODS"] = ["POST", "PUT", "PATCH", "DELETE"]
    app.config["JWT_ACCESS_CSRF_HEADER_NAME"] = "X-CSRF-TOKEN"
    app.config["JWT_REFRESH_CSRF_HEADER_NAME"] = "X-CSRF-TOKEN"
    app.config["JWT_ACCESS_CSRF_COOKIE_NAME"] = "X-CSRF-TOKEN"

    app.config["MAIL_SERVER"] = getenv("MAIL_SERVER")
    app.config["MAIL_PORT"] = getenv("MAIL_PORT")
    app.config["MAIL_USE_TLS"] = getenv("MAIL_USE_TLS")
    app.config["MAIL_USERNAME"] = getenv("MAIL_USERNAME")
    app.config["MAIL_PASSWORD"] = getenv("MAIL_PASSWORD")
    app.config["MAIL_DEFAULT_SENDER"] = getenv("MAIL_DEFAULT_SENDER")

    JWTManager(app)
    mail.init_app(app)

    makedirs(path.join(app.root_path, "logs"), exist_ok=True)
    basicConfig(
        level=INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            FileHandler(path.join(app.root_path, "logs", "authentication.log")),
            StreamHandler(),
        ],
    )
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(poll_blueprint)
    app.register_error_handler(Exception, handle_general_exception)
    app.register_error_handler(DatabaseError, handle_database_errors)
    app.register_error_handler(OperationalError, handle_database_errors)
    app.register_error_handler(IntegrityError, handle_database_errors)
    app.register_error_handler(DataError, handle_database_errors)
    app.register_error_handler(ValidationError, handle_validation_errors)
    app.register_error_handler(CSRFError, handle_csrf_error)
    app.register_error_handler(TypeError, handle_type_error)
    getLogger()
    return app
