"""This module contains the validation error handlers."""

from marshmallow import ValidationError

from app.utils.error_handlers.base_error_handler import handle_error


def handle_validation_errors(error):
    """This function handles validation errors."""
    if isinstance(error, ValidationError):
        errors = [
            f"Error on field {str(error_message).replace('_', ' ').title()}: "
            f"{''.join(error.messages[error_message])}"  # type: ignore
            for error_message in error.messages
        ]
        return handle_error(error, 400, "validation_error", errors)
    raise error
