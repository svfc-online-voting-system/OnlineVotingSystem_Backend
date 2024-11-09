""" Wraps all the database related errors in the application. """

from sqlalchemy.exc import DatabaseError, DataError, OperationalError, IntegrityError

from app.utils.error_handlers.base_error_handler import handle_error


def handle_database_errors(error):
    """This function handles database errors."""
    if isinstance(error, (IntegrityError, DataError, DatabaseError, OperationalError)):
        return handle_error(
            error,
            400,
            "server_error",
            "An error occurred while processing your request.",
        )
    raise error
