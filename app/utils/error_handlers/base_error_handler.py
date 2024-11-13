""" Base error handler for the entire application. """

from logging import getLogger

from app.utils.response_util import set_response

logger = getLogger(__name__)


def handle_error(error, status_code, code, message):
    """Handle errors."""
    logger.error("Error: %s", error)
    return set_response(status_code, {"code": code, "message": message})
