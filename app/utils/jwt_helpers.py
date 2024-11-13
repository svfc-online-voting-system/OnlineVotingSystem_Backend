"""This module contains helper functions for working with JWTs."""

from datetime import datetime, timedelta, timezone

from flask import Flask
from flask_jwt_extended import (
    create_refresh_token,
    create_access_token,
    get_jwt,
    set_access_cookies,
    set_refresh_cookies,
    get_jwt_identity,
)


def refresh_expiring_jwts(response):  # pylint: disable=C0116
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
            refresh_token = create_refresh_token(identity=get_jwt_identity())
            set_refresh_cookies(response, refresh_token)
        return response
    except (RuntimeError, KeyError):
        return response


def add_jwt_after_request_handler(app: Flask):
    """Attaches the JWT refresh logic as an after_request handler."""
    app.after_request(refresh_expiring_jwts)
