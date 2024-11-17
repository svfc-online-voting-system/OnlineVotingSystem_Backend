"""This module contains helper functions for working with JWTs."""

from datetime import datetime, timedelta, timezone
from logging import getLogger

from flask import Flask, Response
from flask_jwt_extended import (
    create_refresh_token,
    create_access_token,
    get_jwt,
    set_access_cookies,
    set_refresh_cookies,
    get_jwt_identity,
)

from flask_jwt_extended.exceptions import InvalidHeaderError

logger = getLogger(__name__)


def refresh_expiring_jwts(response: Response) -> Response:
    """
    Refresh JWT tokens if they're close to expiring.

    Args:
        response: Flask response object
    Returns:
        Response with refreshed tokens if needed
    """
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))

        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
            refresh_token = create_refresh_token(identity=get_jwt_identity())
            set_refresh_cookies(response, refresh_token)
            logger.info("JWT tokens refreshed")

        return response

    except (RuntimeError, KeyError, InvalidHeaderError) as e:
        logger.debug("JWT refresh skipped: %s", e)
        return response


def add_jwt_after_request_handler(app: Flask) -> None:
    """
    Attaches the JWT refresh logic as an after_request handler.

    Args:
        app: Flask application instance
    """
    app.after_request(refresh_expiring_jwts)
