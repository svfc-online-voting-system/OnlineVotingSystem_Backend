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
from sqlalchemy.exc import DataError

from app.exception.email_not_found_error import EmailNotFoundException
from app.exception.email_taken import EmailAlreadyTaken
from app.exception.otp_expired import OTPExpiredException
from app.exception.otp_incorrect import OTPIncorrectException
from app.exception.password_error import PasswordErrorException
from app.exception.token_generation_error import TokenGenerationError
from app.schemas.auth_forms_schema import SignUpSchema, LoginSchema
from app.services.auth_service import AuthService

logger = logging.getLogger(name=__name__)
auth_blueprint = Blueprint('auth', __name__)
auth_service = AuthService()
ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')
is_production = ENVIRONMENT == 'production'


def set_response(status_code, messages, **kwargs):
    """ This function sets the response for the routes. """
    response = make_response(jsonify(messages), status_code)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Date'] = f"{datetime.now()}"
    origin = \
        'https://localhost:4200' if not is_production else 'https://online-voting-system.web.app'
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
    response_data = {'code': 'server_error', 'message': 'Something went wrong on our end.'}
    status_code = 500
    if request.json is None:
        return set_response(400, {'code': 'invalid_request', 'message': 'Bad Request'})
    try:
        registration_data = sign_up_schema.load(request.json)
        if not isinstance(registration_data, dict):
            response_data = {
                'code': 'invalid_data',
                'message': 'Oops we received an invalid and/or malformed data.'
            }
            status_code = 400
            raise ValueError('Invalid data format')
        auth_service_create_account = AuthService()
        authorization_token = auth_service_create_account.register(user_data=registration_data)
        if not authorization_token:
            response_data['message'] = 'Something went wrong on our end.'
            raise TokenGenerationError('Token generation failed')
        return set_response(200, {'code': 'success', 'message': 'Creation Successful'},
                            authorization_token=authorization_token)
    except (ValidationError, ValueError) as ve:
        logger.error("Validation error %s: ", {ve})
        response_data = {'code': 'invalid_data', 'message': ve.messages}
        status_code = 400
    except EmailAlreadyTaken as eat:
        logger.error("Email already taken error %s: ", {eat})
        response_data = {'code': 'email_taken', 'message': 'Wait, that email is already taken.'}
        status_code = 400
    except IntegrityError as int_err:
        logger.error("Integrity error %s: ", {int_err})
    except TokenGenerationError as tge:
        logger.error("Token generation error %s: ", {tge})
        response_data = {'code': 'server_error', 'message': 'Something went wrong on our end.'}
        status_code = 500
    except DataError as data_err:
        logger.error("Data error %s: ", {data_err})
        response_data = {'code': 'invalid_data', 'message': 'Invalid data format'}
        status_code = 400
    except DatabaseError as db_err:
        logger.error("Database error %s: ", {db_err})
    return set_response(status_code, response_data)


@auth_blueprint.route(rule='/auth/login', methods=['POST'])
def login() -> Response:
    """ This is the route for logging in. """
    login_schema = LoginSchema()
    response_data = {'code': 'server_error', 'message': 'Something went wrong on our end.'}
    if request.json is None:
        return set_response(400, {'code': 'invalid_request', 'message': 'Bad Request'})
    if not isinstance(request.json, dict):
        return set_response(400, {'code': 'invalid_data', 'message': 'Invalid data format'})
    try:
        user_data = login_schema.load(request.json)
        if not isinstance(user_data, dict):
            raise ValueError('Invalid data format')
        auth_service_login = AuthService()
        authentication_result = auth_service_login.login(
            user_data.get('email'), user_data.get('password')
        )
        if not authentication_result:
            response_data['message'] = 'Something went wrong on our end.'
        if authentication_result == 'invalid_credentials':
            raise PasswordErrorException
        return set_response(200, {'code': 'success', 'message': f"{authentication_result}"})
    except (ValidationError, ValueError) as ve:
        response_data = {'code': 'invalid_data', 'message': ve.messages}
        status_code = 400
    except PasswordErrorException:
        response_data = {
            'code': 'password_incorrect', 'message': 'You mistyped your password.'
        }
        status_code = 400
    except EmailNotFoundException:
        response_data = {
            'code': 'invalid_email',
            'message': 'Woah, we could not find an account with that email.'
        }
        status_code = 404
    except DatabaseError as db_err:
        logger.error("Database error %s: ", {db_err})
        response_data = {'code': 'server_error', 'message': 'Something went wrong on our end.'}
        status_code = 500
    return set_response(status_code, response_data)


@auth_blueprint.route(rule='/auth/logout', methods=['POST'])
def logout() -> Response:
    """ This is the route for logging out. """
    response = make_response({'code': 'success', 'message': 'Logout Successful'}, 200)
    response.delete_cookie('Authorization')
    return response


@auth_blueprint.route('/auth/verify-jwt-identity', methods=['GET'])
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

@auth_blueprint.route(rule='/auth/otp-verification', methods=["POST"])
def otp_verification() -> Response:
    """ Function for handling otp verification"""
    try:
        email = request.json.get('email')
        otp = request.json.get('otp_code')
        if not email or not otp:
            raise ValueError
        if len(otp) != 7 or not otp.isdigit():
            raise ValueError
        auth_service_otp = AuthService()
        session_token = auth_service_otp.verify_otp(email=email, otp=otp)
        if session_token:
            return set_response(200, {
                'code': 'success',
                'message': 'OTP Verified'
            }, authorization_token=session_token)
        response_data = {'code': 'unauthorized', 'message': 'Unauthorized access.'}
        status_code = 401
    except OTPExpiredException:
        response_data = {'code': 'otp_expired', 'message': 'OTP has expired.'}
        status_code = 400
    except OTPIncorrectException:
        response_data = {'code': 'otp_incorrect', 'message': 'OTP is incorrect.'}
        status_code = 400
    except ValueError:
        response_data = {'code': 'invalid_data', 'message': 'Invalid data format'}
        status_code = 400
    except EmailNotFoundException:
        response_data = {'code': 'email_not_found', 'message': 'Email not found'}
        status_code = 404
    return set_response(status_code, response_data)

@auth_blueprint.route(rule='/auth/generate-otp', methods=["POST"])
def generate_otp() -> Response:
    """ Function for handling otp generation.
    The use-case of this is when the user want to resend
    the otp code that previously sent to the user"""
    try:
        email = request.json.get('email')
        if not email:
            raise ValueError
        auth_service_otp = AuthService()
        if auth_service_otp.generate_otp(email=email):
            return set_response(200, {
                'code': 'success',
                'message': 'OTP Generated'
            })
        response_data = {'code': 'unauthorized', 'message': 'Unauthorized access.'}
        status_code = 401
    except ValueError:
        response_data = {'code': 'invalid_data', 'message': 'Invalid data format'}
        status_code = 400
    except EmailNotFoundException:
        response_data = {'code': 'email_not_found', 'message': 'Email not found'}
        status_code = 404
    return set_response(status_code, response_data)
