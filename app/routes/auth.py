"""
        This module contains the routes for the authentication of users.
"""
import logging
from datetime import datetime, timedelta
import os
from sqlite3 import IntegrityError, DatabaseError

from flask import Blueprint, request, Response, make_response, json, jsonify
from marshmallow import ValidationError

from app.exception.email_not_found_error import EmailNotFound
from app.exception.email_taken import EmailAlreadyTaken
from app.exception.password_error import PasswordError
from app.exception.token_generation_error import TokenGenerationError
from app.schemas.auth_forms_schema import SignUpSchema, LoginSchema
from app.services.auth_service import AuthService

logger = logging.getLogger(name=__name__)
auth_blueprint = Blueprint('auth', __name__)
auth_service = AuthService()
ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')
is_production = ENVIRONMENT == 'production'


def set_response(status_code, messages, **kwargs):
    """Helper function to create a standard response."""
    response = make_response(jsonify(messages), status_code)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Date'] = f"{datetime.now()}"
    if 'authorization_token' in kwargs:
        # Setting the token in a cookie
        expires = datetime.now() + timedelta(days=3)
        response.set_cookie(
            'auth-token',
            kwargs['authorization_token'],
            httponly=True,
            secure=is_production,
            samesite='Strict',
            expires=expires
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
    status_code = 500  # Default status code for errors
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
        # Successful creation
        return set_response(200, {'code': 'success', 'message': 'Creation Successful'},
                            authorization_token=f'Bearer {authorization_token}')
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
    except DatabaseError as db_err:
        logger.error("Database error %s: ", {db_err})
    return set_response(status_code, response_data)


@auth_blueprint.route(rule='/auth/login', methods=['POST'])
def login() -> Response:
    """ This is the route for logging in. """
    login_schema = LoginSchema()
    response_data = {'code': 'server_error', 'message': 'Something went wrong on our end.'}
    status_code = 500  # Default status code for errors
    if request.json is None:
        return set_response(400, {'code': 'invalid_request', 'message': 'Bad Request'})
    if not isinstance(request.json, dict):
        return set_response(400, {'code': 'invalid_data', 'message': 'Invalid data format'})
    try:
        user_data = login_schema.load(request.json)
        if not isinstance(user_data, dict):
            response_data = {
                'code': 'invalid_data',
                'message': 'Oops we received an invalid and/or malformed data.'
            }
            status_code = 400
            raise ValueError('Invalid data format')
        auth_service_login = AuthService()
        authorization_token = auth_service_login.login(
            user_data.get('email'), user_data.get('password')
        )
        if not authorization_token:
            response_data['message'] = 'Something went wrong on our end.'
            raise TokenGenerationError('Token generation failed')
        # Successful login
        return set_response(200, {'code': 'success', 'message': 'Login Successful'},
                            authorization_token=f'Bearer {authorization_token}')
    except (ValidationError, ValueError) as ve:
        response_data = {'code': 'invalid_data', 'message': ve.messages}
        status_code = 400
    except PasswordError:
        response_data = {
            'code': 'password_incorrect', 'message': 'Probably you mistyped your password.'
        }
        status_code = 400
    except EmailNotFound:
        response_data = {
            'code': 'invalid_email',
            'message': 'Woah, we could not find an account with that email.'
        }
        status_code = 404
    except TokenGenerationError as tge:
        logger.error("Token generation error %s: ", {tge})
        response_data = {'code': 'server_error', 'message': 'Something went wrong on our end.'}
        status_code = 500
    except DatabaseError as db_err:
        logger.error("Database error %s: ", {db_err})
        response_data = {'code': 'server_error', 'message': 'Something went wrong on our end.'}
        status_code = 500
    return set_response(status_code, response_data)


@auth_blueprint.route(rule='/auth/logout', methods=['POST'])
def logout() -> Response:
    """ This is the route for logging out. """
    response = make_response({'code': 'success', 'message': 'Logout Successful'}, 200)
    response.delete_cookie('auth-token')
    return response
