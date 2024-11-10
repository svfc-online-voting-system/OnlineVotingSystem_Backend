"""This module registers system-wide error handlers to prevent redundancy across blueprints."""

from flask import Flask
from marshmallow import ValidationError
from flask_jwt_extended.exceptions import CSRFError
from sqlalchemy.exc import IntegrityError, DataError, DatabaseError, OperationalError

from app.utils.error_handlers.jwt_error_handlers import handle_csrf_error
from app.utils.error_handlers.database_error_handlers import handle_database_errors
from app.utils.error_handlers.validation_error_handler import handle_validation_errors
from app.utils.error_handlers.general_error_handler import (
    handle_general_exception,
    handle_type_error,
)


def register_system_wide_errors(app: Flask):
    """Register system-wide error handlers to prevent redundancy across blueprints."""
    app.register_error_handler(Exception, handle_general_exception)
    app.register_error_handler(DatabaseError, handle_database_errors)
    app.register_error_handler(OperationalError, handle_database_errors)
    app.register_error_handler(IntegrityError, handle_database_errors)
    app.register_error_handler(DataError, handle_database_errors)
    app.register_error_handler(ValidationError, handle_validation_errors)
    app.register_error_handler(CSRFError, handle_csrf_error)
    app.register_error_handler(TypeError, handle_type_error)
