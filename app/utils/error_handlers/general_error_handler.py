"""Wraps the general, uncaught exceptions in the application."""

from app.utils.error_handlers.base_error_handler import handle_error


def handle_general_exception(error):
    """This function handles general exceptions."""
    return handle_error(
        error,
        "unexpected_error",
        "An unexpected error occurred. Please try again later.",
        500,
    )


def handle_type_error(error):
    """This function handles type errors."""
    if isinstance(error, TypeError):
        return handle_error(
            error,
            "type_error",
            "Type error occurred.",
            400,
        )
    raise error
