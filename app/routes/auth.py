"""
        This module contains the routes for the authentication of users.
"""
import logging
from datetime import datetime, timedelta
import os
from sqlite3 import IntegrityError, DatabaseError

from flask import Blueprint, request, Response, make_response, json, jsonify
from jwt import ExpiredSignatureError, InvalidTokenError
from marshmallow import ValidationError
from sqlalchemy.exc import DataError, OperationalError

from app.exception.authorization_exception import (EmailNotFoundException, OTPExpiredException,
                                                   OTPIncorrectException,
                                                   PasswordResetExpiredException,
                                                   PasswordResetLinkInvalidException,
                                                   EmailAlreadyTaken,
                                                   PasswordIncorrectException,
                                                   AccountNotVerifiedException)
from app.schemas.auth_forms_schema import SignUpSchema, LoginSchema
from app.services.auth_service import AuthService

logger = logging.getLogger(name=__name__)
auth_blueprint = Blueprint('auth', __name__)
auth_service = AuthService()
ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')
is_production = ENVIRONMENT == 'production'


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


auth_blueprint.register_error_handler(Exception, handle_database_errors)
auth_blueprint.register_error_handler(ValueError, handle_value_error)
auth_blueprint.register_error_handler(ValidationError, handle_validation_error)
auth_blueprint.register_error_handler(EmailAlreadyTaken, handle_email_already_taken)
auth_blueprint.register_error_handler(PasswordIncorrectException,
                                      handle_password_incorrect_exception)
auth_blueprint.register_error_handler(AccountNotVerifiedException,
                                      handle_account_not_verified_exception)
auth_blueprint.register_error_handler(EmailNotFoundException, handle_email_not_found)
auth_blueprint.register_error_handler(OTPExpiredException, handle_otp_expired_exception)
auth_blueprint.register_error_handler(OTPIncorrectException, handle_otp_incorrect_exception)
auth_blueprint.register_error_handler(PasswordResetExpiredException,
                                      handle_password_reset_expired_exception)
auth_blueprint.register_error_handler(PasswordResetLinkInvalidException,
                                      handle_password_reset_link_invalid_exception)
auth_blueprint.register_error_handler(Exception, handle_general_exception)


def set_response(status_code, messages, **kwargs):
    """ This function sets the response for the routes. """
    response = make_response(jsonify(messages), status_code)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Date'] = f"{datetime.now()}"
    origin = 'https://localhost:4200' if not is_production else \
        'https://online-voting-system.web.app'
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS, GET, DELETE, PUT'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    if 'authorization_token' in kwargs:
        expires = datetime.now() + timedelta(days=365)
        response.set_cookie(
            key='Authorization',
            value=kwargs['authorization_token'],
            httponly=True,
            secure=True,
            samesite='None',
            expires=expires,
            path='/'
        )
    response_data = json.dumps(messages)
    response.data = response_data
    response.status_code = status_code
    response.headers["Content-Length"] = str(len(response_data))
    return response


@auth_blueprint.route(rule='/auth/create-account', methods=['POST'])
def create_account() -> Response:
    """ This is the route for creating an account. """
    sign_up_schema = SignUpSchema()
    if request.json is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    registration_data = sign_up_schema.load(request.json)
    if not isinstance(registration_data, dict):
        raise ValueError('Invalid data format')
    auth_service_create_account = AuthService()
    result = auth_service_create_account.register(user_data=registration_data)
    if not result:
        return set_response(500, {
            'code': 'server_error',
            'message': 'Something went wrong on our end.'
        })
    return set_response(200, {
        'code': 'success',
        'message': 'Open your email for verification.'
    })

@auth_blueprint.route(rule='/auth/login', methods=['POST'])
def login() -> Response:
    """ This is the route for logging in. """
    login_schema = LoginSchema()
    if request.json is None:
        return set_response(400, {'code': 'invalid_request', 'message': 'Bad Request'})
    if not isinstance(request.json, dict):
        return set_response(400, {'code': 'invalid_data', 'message': 'Invalid data format'})
    user_data = login_schema.load(request.json)
    if not isinstance(user_data, dict):
        raise ValueError('Invalid data format')
    auth_service_login = AuthService()
    authentication_result = auth_service_login.login(
        user_data.get('email'), user_data.get('password')
    )
    if not authentication_result:
        return set_response(500, {
            'code': 'server_error',
            'message': 'Something went wrong on our end.'
        })
    if authentication_result == 'invalid_credentials':
        raise PasswordIncorrectException('Invalid credentials')
    return set_response(200, {
        'code': 'success',
        'message': "OTP has been sent to your email."
    })



@auth_blueprint.route(rule='/auth/logout', methods=['POST'])
def logout() -> Response:
    """ This is the route for logging out. """
    response = make_response({'code': 'success', 'message': 'Logout Successful'}, 200)
    response.delete_cookie('Authorization')
    return response


@auth_blueprint.route(rule='/auth/verify-jwt-identity', methods=['GET'])
def verify_jwt_identity() -> Response:
    """ This is the route for verifying the JWT identity. """
    try:
        auth_service_verify_token = AuthService()
        result = auth_service_verify_token.verify_token()
        if result:
            return set_response(200, {'code': 'success', 'message': 'JWT Identity verified.'})
        return set_response(401, {'code': 'unauthorized', 'message': 'Unauthorized access.'})
    except ExpiredSignatureError:
        logger.warning("JWT token has expired")
        return set_response(401,
                            {'code': 'token_expired',
                             'message': 'Your session has expired. Please log in again.'}
                            )
    except InvalidTokenError:
        logger.warning("Invalid JWT token")
        return set_response(401,
                            {'code': 'invalid_token',
                             'message': 'Invalid authentication token.'}
                            )

@auth_blueprint.route(rule='/auth/verify-token-reset-password', methods=['POST'])
def verify_token_reset_password():
    """ Function for handling token verification for password reset."""
    token = request.json.get('token')
    new_password = request.json.get('new_password')
    if not token or not new_password:
        raise ValueError('Invalid data format')
    if len(new_password) < 8:
        raise PasswordIncorrectException('Password must be at least 8 characters.')
    auth_service_token = AuthService()
    if auth_service_token.verify_forgot_password_token(token, new_password):
        return set_response(200, {
            'code': 'success',
            'message': 'Token Verified'
        })
    return set_response(401, {
        'code': 'unauthorized',
        'message': 'Unauthorized access.'
    })


@auth_blueprint.route(rule='/auth/forgot-password', methods=['POST'])
def forgot_password():
    """ Function for handling forgot password."""
    email = request.json.get('email')
    if not email:
        raise ValueError
    auth_service_forgot_password = AuthService()
    if auth_service_forgot_password.send_forgot_password_link(email):
        return set_response(200, {
            'code': 'success',
            'message': 'Password reset link sent'
        })
    return set_response(401, {
        'code': 'unauthorized',
        'message': 'Unauthorized access.'
    })

@auth_blueprint.route(rule='/auth/otp-verification', methods=["POST"])
def otp_verification() -> Response:
    """ Function for handling otp verification"""
    email = request.json.get('email')
    otp = request.json.get('otp_code')
    if not email or not otp or len(otp) != 7 or not otp.isdigit():
        raise ValueError('Invalid data format')
    auth_service_otp = AuthService()
    session_token = auth_service_otp.verify_otp(email=email, otp=otp)
    if session_token:
        return set_response(200, {
            'code': 'success',
            'message': 'OTP Verified'
        }, authorization_token=session_token)
    return set_response(401, {
        'code': 'unauthorized',
        'message': 'Unauthorized access.'
    })

@auth_blueprint.route(rule='/auth/generate-otp', methods=["POST"])
def generate_otp() -> Response:
    """ Function for handling otp generation.
    The use-case of this is when the user want to resend
    the otp code that previously sent to the user"""
    email = request.json.get('email')
    if not email:
        raise ValueError('Invalid data format')
    auth_service_otp = AuthService()
    if auth_service_otp.generate_otp(email=email):
        return set_response(200, {
            'code': 'success',
            'message': 'OTP Generated'
        })
    return set_response(401, {
        'code': 'unauthorized',
        'message': 'Unauthorized access.'
    })

@auth_blueprint.route(rule='/auth/verify-email', methods=['GET'])
def verify_email() -> Response:
    """ Function for handling email verification.
    https://domain.com/auth/verify-email?email=someone@example.com&token=sometoken
    """
    email = request.args.get('email')
    token = request.args.get('token')
    if not email or not token:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: Missing email or token.'
        })
    auth_service_verify_email = AuthService()
    if auth_service_verify_email.verify_email(email, token):
        return set_response(200, {
            'code': 'success',
            'message': 'Email Verified'
        })
    return set_response(401, {
        'code': 'unauthorized',
        'message': 'Unauthorized access.'
    })

@auth_blueprint.route(rule='/auth/resend-verification-email', methods=['POST'])
def resend_verification_email() -> Response:
    """ Function for handling email verification."""
    email = request.json.get('email')
    if not email:
        raise ValueError('Invalid data format')
    auth_service_resend_verification_email = AuthService()
    if auth_service_resend_verification_email.resend_email_verification(email):
        return set_response(200, {
            'code': 'success',
            'message': 'Email Verification Sent'
        })
    return set_response(401, {
        'code': 'unauthorized',
        'message': 'Unauthorized access.'
    })
