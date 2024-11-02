""" This module contains error handlers for the application. """
from logging import getLogger
from os import getenv

from flask_jwt_extended.exceptions import CSRFError
from flask_jwt_extended.exceptions import (
    NoAuthorizationError, InvalidHeaderError,
    WrongTokenError, JWTDecodeError,
    UserClaimsVerificationError
)
from marshmallow import ValidationError
from sqlalchemy.exc import DataError, IntegrityError, DatabaseError, OperationalError

from app.exception.authorization_exception import (
    EmailNotFoundException, OTPExpiredException,
    OTPIncorrectException, PasswordResetExpiredException,
    PasswordResetLinkInvalidException, EmailAlreadyTaken,
    PasswordIncorrectException, AccountNotVerifiedException
)
from app.exception.voting_event_exception import VotingEventDoesNotExists
from app.utils.response_utils import set_response

logger = getLogger(__name__)
ENVIRONMENT = getenv('ENVIRONMENT', 'development')
is_production = ENVIRONMENT == 'production'


def handle_database_errors(error):
    """ This function handles database errors. """
    if isinstance(error, (IntegrityError, DataError, DatabaseError, OperationalError)):
        logger.error("Database error: %s", error)
        return set_response(500, {
            'code': 'server_error',
            'message': 'A database error occurred. Please try again later.'
        })
    raise error


def handle_general_exception(error):
    """ This function handles general exceptions. """
    logger.error("General exception: %s", error)
    return set_response(500, {
        'code': 'unexpected_error',
        'message': 'An unexpected error occurred. Please try again later.'
    })


def handle_validation_error(error):
    """ This function handles validation errors. """
    if isinstance(error, ValidationError):
        logger.error("Validation error: %s", error)
        return set_response(400, {
            'code': 'invalid_data',
            'message': error.messages
        })
    raise error


def handle_account_not_verified_exception(error):
    """ This function handles account not verified exceptions. """
    if isinstance(error, AccountNotVerifiedException):
        logger.error("Account not verified: %s", error)
        return set_response(401, {
            'code': 'account_not_verified',
            'message': 'Account not verified.'
        })
    raise error


def handle_email_not_found(error):
    """ This function handles email not found exceptions. """
    if isinstance(error, EmailNotFoundException):
        logger.error("Email not found: %s", error)
        return set_response(404, {
            'code': 'email_not_found',
            'message': 'Email not found.'
        })
    raise error


def handle_otp_expired_exception(error):
    """ This function handles OTP expired exceptions. """
    if isinstance(error, OTPExpiredException):
        logger.error("OTP expired: %s", error)
        return set_response(400, {
            'code': 'otp_expired',
            'message': 'OTP has expired.'
        })
    raise error


def handle_otp_incorrect_exception(error):
    """ This function handles OTP incorrect exceptions. """
    if isinstance(error, OTPIncorrectException):
        logger.error("OTP incorrect: %s", error)
        return set_response(400, {
            'code': 'otp_incorrect',
            'message': 'OTP is incorrect.'
        })
    raise error


def handle_password_reset_expired_exception(error):
    """ This function handles password reset expired exceptions. """
    if isinstance(error, PasswordResetExpiredException):
        logger.error("Password reset expired: %s", error)
        return set_response(400, {
            'code': 'password_reset_expired',
            'message': 'Password reset link has expired.'
        })
    raise error


def handle_password_reset_link_invalid_exception(error):
    """ This function handles password reset link invalid exceptions. """
    if isinstance(error, PasswordResetLinkInvalidException):
        logger.error("Password reset link invalid: %s", error)
        return set_response(400, {
            'code': 'password_reset_link_invalid',
            'message': 'Password reset link is invalid.'
        })
    raise error


def handle_password_incorrect_exception(error):
    """ This function handles password errors. """
    if isinstance(error, PasswordIncorrectException):
        logger.error("Password error: %s", error)
        return set_response(400, {
            'code': 'password_error',
            'message': 'Invalid credentials.'
        })
    raise error


def handle_value_error(error):
    """ This function handles value errors. """
    if isinstance(error, ValueError):
        logger.error("Value error: %s", error)
        return set_response(400, {
            'code': 'invalid_data',
            'message': 'Invalid data format.'
        })
    raise error


def handle_email_already_taken(error):
    """ This function handles email already taken errors. """
    if isinstance(error, EmailAlreadyTaken):
        logger.error("Email already taken: %s", error)
        return set_response(400, {
            'code': 'email_already_taken',
            'message': 'Email already taken.'
        })
    raise error


def handle_no_authorization_error(error):
    """ This function handles no authorization errors. """
    if isinstance(error, NoAuthorizationError):
        logger.error("No authorization error: %s", error)
        return set_response(401, {
            'code': 'no_authorization',
            'message': 'No authorization header provided.'
        })
    raise error


def handle_invalid_header_error(error):
    """ This function handles invalid header errors. """
    if isinstance(error, InvalidHeaderError):
        logger.error("Invalid header error: %s", error)
        return set_response(401, {
            'code': 'invalid_header',
            'message': 'Invalid authorization header.'
        })
    raise error


def handle_wrong_token_error(error):
    """ This function handles wrong token errors. """
    if isinstance(error, WrongTokenError):
        logger.error("Wrong token error: %s", error)
        return set_response(401, {
            'code': 'wrong_token',
            'message': 'Invalid token.'
        })
    raise error


def handle_jwt_decode_error(error):
    """ This function handles JWT decode errors. """
    if isinstance(error, JWTDecodeError):
        logger.error("JWT decode error: %s", error)
        return set_response(401, {
            'code': 'jwt_decode_error',
            'message': 'Invalid token.'
        })
    raise error


def handle_user_claims_verification_error(error):
    """ This function handles user claims verification errors. """
    if isinstance(error, UserClaimsVerificationError):
        logger.error("User claims verification error: %s", error)
        return set_response(401, {
            'code': 'user_claims_verification_error',
            'message': 'Invalid token.'
        })
    raise error

def handle_csrf_error(error):
    """ This function handles CSRF errors. """
    if isinstance(error, CSRFError):
        logger.error("CSRF error: %s", error)
        return set_response(403, {
            'code': 'csrf_error',
            'message': 'CSRF token is missing or incorrect.'
        })
    raise error

def handle_voting_event_does_not_exists(error):
    """ This function handles voting event does not exist errors. """
    if isinstance(error, VotingEventDoesNotExists):
        logger.error("Voting event does not exists: %s", error)
        return set_response(404, {
            'code': 'voting_event_does_not_exists',
            'message': 'Voting event does not exists.'
        })
    raise error
