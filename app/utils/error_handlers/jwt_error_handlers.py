""" JWT Error handler wrapper. """

from flask_jwt_extended.exceptions import (
    CSRFError,
    NoAuthorizationError,
    JWTDecodeError,
    WrongTokenError,
    RevokedTokenError,
    UserClaimsVerificationError,
    UserLookupError,
    InvalidHeaderError,
    InvalidQueryParamError,
    FreshTokenRequired,
)

from app.utils.error_handlers.base_error_handler import handle_error


def handle_csrf_error(error):
    """This function handles CSRF errors."""
    if isinstance(error, CSRFError):
        return handle_error(
            error, 400, "csrf_error", "Cross-Site Request Forgery error."
        )
    raise error


def handle_no_authorization_error(error):
    """This function handles no authorization errors."""
    if isinstance(error, NoAuthorizationError):
        return handle_error(
            error, 401, "no_authorization_error", "No authorization provided."
        )
    raise error


def handle_jwt_decode_error(error):
    """This function handles JWT decode errors."""
    if isinstance(error, JWTDecodeError):
        return handle_error(error, 401, "jwt_decode_error", "Invalid or expired token.")
    raise error


def handle_wrong_token_error(error):
    """This function handles wrong token errors."""
    if isinstance(error, WrongTokenError):
        return handle_error(error, 400, "wrong_token_error", "Invalid token provided.")
    raise error


def handle_revoked_token_error(error):
    """This function handles revoked token errors."""
    if isinstance(error, RevokedTokenError):
        return handle_error(
            error,
            400,
            "revoked_token_error",
            "Revoked token provided, please reauthenticate.",
        )
    raise error


def handle_user_claims_verification_error(error):
    """This function handles user claims verification errors."""
    if isinstance(error, UserClaimsVerificationError):
        return handle_error(
            error,
            400,
            "user_claims_verification_error",
            "User claims verification error.",
        )
    raise error


def handle_user_lookup_error(error):
    """This function handles user lookup errors."""
    if isinstance(error, UserLookupError):
        return handle_error(error, 400, "user_lookup_error", "User lookup error.")
    raise error


def handle_invalid_header_error(error):
    """This function handles invalid header errors."""
    if isinstance(error, InvalidHeaderError):
        return handle_error(error, 400, "invalid_header_error", "Invalid header error.")
    raise error


def handle_invalid_query_param_error(error):
    """This function handles invalid query param errors."""
    if isinstance(error, InvalidQueryParamError):
        return handle_error(
            error, 400, "invalid_query_param_error", "Invalid query param."
        )
    raise error


def handle_fresh_token_required(error):
    """This function handles fresh token required errors."""
    if isinstance(error, FreshTokenRequired):
        return handle_error(error, 400, "fresh_token_required", "Fresh token required.")
    raise error
