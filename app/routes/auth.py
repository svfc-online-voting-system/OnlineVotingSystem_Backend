""" This module contains the routes for the authentication of users. """
from logging import getLogger
from flask import Blueprint, request, Response, make_response, jsonify
from jwt import ExpiredSignatureError, InvalidTokenError
from marshmallow import ValidationError
from app.extension import csrf
from app.exception.authorization_exception import (EmailNotFoundException, OTPExpiredException,
                                                   OTPIncorrectException,
                                                   PasswordResetExpiredException,
                                                   PasswordResetLinkInvalidException,
                                                   EmailAlreadyTaken,
                                                   PasswordIncorrectException,
                                                   AccountNotVerifiedException)
from flask_jwt_extended.exceptions import NoAuthorizationError
from app.schemas.auth_forms_schema import SignUpSchema, LoginSchema
from app.services.auth_service import AuthService
from app.utils.error_handlers import (handle_account_not_verified_exception, handle_general_exception,
                                      handle_password_incorrect_exception, handle_otp_incorrect_exception,
                                      handle_otp_expired_exception, handle_email_not_found,
                                      handle_password_reset_expired_exception,
                                      handle_password_reset_link_invalid_exception, handle_email_already_taken,
                                      handle_value_error, handle_database_errors, handle_validation_error,
                                      handle_no_authorization_error)
from app.utils.response_utils import set_response

logger = getLogger(name=__name__)
auth_blueprint = Blueprint('auth', __name__)
auth_service = AuthService()

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
auth_blueprint.register_error_handler(NoAuthorizationError, handle_no_authorization_error)
auth_blueprint.register_error_handler(Exception, handle_general_exception)

@auth_blueprint.route(rule='/auth/create-account', methods=['POST'])
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

@auth_blueprint.route(rule='/auth/logout', methods=['POST'])
def logout() -> Response:
    """ This is the route for logging out. """
    response = make_response()
    response.delete_cookie('Authorization', secure=True, samesite='None', path='/', httponly=True)
    response.delete_cookie('X-CSRFToken',   secure=True, samesite='None', path='/', httponly=True)
    response.delete_cookie('session', secure=True, samesite='None', path='/', httponly=True)
    res_body = jsonify({
        'code': 'success',
        'message': 'Logged out successfully.'
    })
    response.data = res_body
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

@auth_blueprint.route(rule='/auth/verify-token-reset-password', methods=['PATCH'])
@csrf.exempt
def verify_token_reset_password():
    """ Function for handling token verification for password reset. """
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

@auth_blueprint.route(rule='/auth/forgot-password', methods=['PATCH'])
@csrf.exempt
def forgot_password():
    """ Function for handling forgot password. """
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

@auth_blueprint.route(rule='/auth/otp-verification', methods=["PATCH"])
@csrf.exempt
def otp_verification() -> Response:
    """ Function for handling otp verification"""
    email = request.json.get('email')
    otp = str(request.json.get('otp_code'))
    if not email or not otp or len(otp) != 7 or not otp.isdigit():
        raise ValueError('Invalid data format')
    auth_service_otp = AuthService()
    session_token, csrf_token = auth_service_otp.verify_otp(email=email, otp=otp)
    if session_token and csrf_token:
        return set_response(200, {
            'code': 'success',
            'message': 'OTP Verified'
        }, authorization_token=session_token, csrf_token=csrf_token)
    return set_response(401, {
        'code': 'unauthorized',
        'message': 'Unauthorized access.'
    })

@auth_blueprint.route(rule='/auth/generate-otp', methods=["PATCH"])
@csrf.exempt
def generate_otp() -> Response:
    """ Function for handling otp generation.
    The use-case of this is when the user want to resend
    the otp code that previously sent to the user. """
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

@auth_blueprint.route('/auth/verify-email/<string:token>', methods=['GET'])
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

@auth_blueprint.route(rule='/auth/resend-verification-email', methods=['PATCH'])
@csrf.exempt
def resend_verification_email() -> Response:
    """ Function for handling email verification. """
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
