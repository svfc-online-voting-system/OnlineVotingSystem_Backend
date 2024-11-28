"""This module contains helper functions for working with JWTs."""

from datetime import datetime, timedelta, timezone
from logging import getLogger

from flask import Flask, Response
from flask_jwt_extended import (
    get_jwt,
    set_access_cookies,
    set_refresh_cookies,
    get_jwt_identity,
)

from flask_jwt_extended.exceptions import InvalidHeaderError

from app.services.token_service import TokenService

logger = getLogger(__name__)


def refresh_expiring_jwts(response: Response) -> Response:
    """
    Refresh JWT and CSRF tokens if they're close to expiring.

    Args:
        response: Flask response object
    Returns:
        Response with refreshed tokens if needed
    """
    try:
        # Get current JWT claims
        jwt_data = get_jwt()
        exp_timestamp = jwt_data["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))

        if target_timestamp > exp_timestamp:
            # Get identity from current token
            identity = get_jwt_identity()
            role = jwt_data["sub"].get("role")

            # Generate new tokens with same claims
            token_service = TokenService()
            access_token, refresh_token = token_service.generate_jwt_csrf_token(
                email=identity["email"], user_id=identity["user_id"], role=role
            )

            # Set new tokens in cookies
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)

            logger.info("JWT and CSRF tokens refreshed")

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
