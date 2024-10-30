""" This module contains the routes for the authentication of users. """
from logging import getLogger
from flask import Blueprint, request, Response

from flask_wtf.csrf import validate_csrf
from flask_jwt_extended import jwt_required
from flask_jwt_extended.exceptions import CSRFError, NoAuthorizationError
from jwt import ExpiredSignatureError, InvalidTokenError
from marshmallow import ValidationError

from app.exception.authorization_exception import (
    AccountNotVerifiedException, EmailAlreadyTaken, EmailNotFoundException,
    OTPExpiredException, OTPIncorrectException, PasswordIncorrectException,
    PasswordResetExpiredException, PasswordResetLinkInvalidException
)
from app.extension import csrf
from app.schemas.auth_forms_schema import LoginSchema, SignUpSchema
from app.services.auth_service import AuthService
from app.utils.error_handlers import (
    handle_account_not_verified_exception, handle_csrf_error, handle_email_already_taken,
    handle_email_not_found, handle_general_exception, handle_no_authorization_error,
    handle_otp_expired_exception, handle_otp_incorrect_exception, handle_password_incorrect_exception,
    handle_password_reset_expired_exception, handle_password_reset_link_invalid_exception,
    handle_validation_error, handle_value_error
)
from app.utils.response_utils import set_response

logger = getLogger(name=__name__)
auth_blueprint = Blueprint('auth', __name__)
auth_service = AuthService()

auth_blueprint.register_error_handler(ValueError, handle_value_error)
auth_blueprint.register_error_handler(ValidationError, handle_validation_error)
auth_blueprint.register_error_handler(
    EmailAlreadyTaken, handle_email_already_taken)
auth_blueprint.register_error_handler(
    PasswordIncorrectException, handle_password_incorrect_exception)
auth_blueprint.register_error_handler(
    AccountNotVerifiedException, handle_account_not_verified_exception)
auth_blueprint.register_error_handler(
    EmailNotFoundException, handle_email_not_found)
auth_blueprint.register_error_handler(
    OTPExpiredException, handle_otp_expired_exception)
auth_blueprint.register_error_handler(
    OTPIncorrectException, handle_otp_incorrect_exception)
auth_blueprint.register_error_handler(
    PasswordResetExpiredException, handle_password_reset_expired_exception)
auth_blueprint.register_error_handler(
    PasswordResetLinkInvalidException, handle_password_reset_link_invalid_exception)
auth_blueprint.register_error_handler(
    NoAuthorizationError, handle_no_authorization_error)
auth_blueprint.register_error_handler(Exception, handle_general_exception)
auth_blueprint.register_error_handler(CSRFError, handle_csrf_error)


@auth_blueprint.route(rule='/v1/auth/create-account', methods=['POST'])
@csrf.exempt
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
    if result is None:
        return set_response(500, {
            'code': 'server_error',
            'message': 'Something went wrong on our end.'
        })
    return set_response(200, {
        'code': 'success',
        'message': 'Open your email for verification.'
    })


@auth_blueprint.route(rule='/v1/auth/login', methods=['POST'])
@csrf.exempt
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
        'code': 'otp_sent',
        'message': "OTP has been sent to your email."
    })


@auth_blueprint.route(rule='/v1/auth/logout', methods=['POST'])
@jwt_required(optional=False)
def logout() -> Response:
    """ This is the route for logging out. """
    return set_response(200, {
        'code': 'success',
        'message': 'Logged out successfully.'
    }, action='logout')


@auth_blueprint.route(rule='/v1/auth/verify-jwt-identity', methods=['GET'])
@jwt_required(optional=True)
def verify_jwt_identity() -> Response:
    """ This is the route for verifying the JWT identity. """
    csrf_token = request.headers.get('X-CSRF-TOKEN')
    try:
        validate_csrf(csrf_token)
        return set_response(200, {
            'code': 'success',
            'message': 'Token Verified'
        })
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


@auth_blueprint.route(rule='/v1/auth/verify-token-reset-password', methods=['PATCH'])
@jwt_required(optional=True)
def verify_token_reset_password():
    """ Function for handling token verification for password reset. """
    data = request.json
    if data is None:
        raise ValueError('Invalid data format')
    token = data.get('token')
    new_password = data.get('new_password')
    if not token or not new_password:
        raise ValueError('Invalid data format')
    if len(new_password) < 8:
        raise PasswordIncorrectException(
            'Password must be at least 8 characters.')
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


@auth_blueprint.route(rule='/v1/auth/forgot-password', methods=['PATCH'])
@jwt_required(optional=True)
def forgot_password():
    """ Function for handling forgot password. """
    data = request.json
    if not data:
        raise ValueError('Invalid data format')
    email = data.get('email')
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


@auth_blueprint.route(rule='/v1/auth/otp-verification', methods=["PATCH"])
@csrf.exempt
def otp_verification() -> Response:
    """ Function for handling otp verification"""
    data = request.json
    if not data:
        raise ValueError('Invalid data format')
    email = data.get('email')
    otp = str(data.get('otp_code'))
    if not email or not otp or len(otp) != 7 or not otp.isdigit():
        raise ValueError('Invalid data format')
    auth_service_otp = AuthService()
    result = auth_service_otp.verify_otp(email=email, otp=otp)
    if result is None:
        return set_response(500, {
            'code': 'server_error',
            'message': 'Something went wrong on our end.'
        })
    session_token, csrf_token = result
    if session_token and csrf_token:
        return set_response(200, {
            'code': 'success',
            'message': 'OTP Verified'
        }, authorization_token=session_token, csrf_token=csrf_token)
    return set_response(401, {
        'code': 'unauthorized',
        'message': 'Unauthorized access.'
    })


@auth_blueprint.route(rule='/v1/auth/generate-otp', methods=["PATCH"])
@jwt_required(optional=True)
def generate_otp() -> Response:
    """ Function for handling otp generation.
    The use-case of this is when the user want to resend
    the otp code that previously sent to the user. """
    data = request.json
    if not data:
        raise ValueError('Invalid data format')
    email = data.get('email')
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


@auth_blueprint.route('/v1/auth/verify-email/<string:token>', methods=['GET'])
def verify_email(token: str) -> Response:
    """ Function for handling email verification. """
    if len(token) != 171:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: Invalid token.'
        })
    if not token:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: Missing token.'
        })
    auth_service_verify_email = AuthService()
    if auth_service_verify_email.verify_email(token):
        return set_response(200, {
            'code': 'success',
            'message': 'Email Verified'
        })
    return set_response(401, {
        'code': 'unauthorized',
        'message': 'Unauthorized access.'
    })


@auth_blueprint.route(rule='/v1/auth/resend-verification-email', methods=['PATCH'])
@jwt_required(optional=True)
def resend_verification_email() -> Response:
    """ Function for handling email verification. """
    data = request.json
    if not data:
        raise ValueError('Invalid data format')
    email = data.get('email')
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
