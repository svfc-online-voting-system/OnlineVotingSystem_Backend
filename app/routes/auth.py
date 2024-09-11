"""
        This module contains the routes for the authentication of users.
"""

from sqlite3 import IntegrityError, DatabaseError
import logging
from flask import Blueprint, request, jsonify, Response, make_response
from marshmallow import ValidationError
from app.exception.email_taken import EmailAlreadyTaken
from app.exception.password_error import PasswordError
from app.exception.email_not_found import EmailNotFound
from app.services.auth_service import AuthService
from app.schemas.auth_forms_schema import SignUpSchema, LoginSchema


logger = logging.getLogger(name=__name__)
auth_blueprint = Blueprint('auth', __name__)
auth_service = AuthService()


@auth_blueprint.route(rule='/auth/create-account', methods=['POST'])
def create_account() -> Response:
    """ This is the route for creating an account. """
    sign_up_schema = SignUpSchema()
    status = 200
    if request.json is None:
        return jsonify([{'status': 400, 'message': 'Bad Request'}], status=400, mimetypes="application/json")

    response = {'status': 400, 'message': 'Bad Request'}
    try:
        registration_data = sign_up_schema.load(request.json)
        if not isinstance(registration_data, dict):
            return make_response(jsonify({'message': 'Bad Request, validation error.'}), 400)

        first_name = str(object=registration_data.get('firstname'))
        last_name = str(object=registration_data.get('lastname'))
        email = str(object=registration_data.get('email'))
        plaintext_password = str(object=registration_data.get('password'))
        date_of_birth = registration_data.get('date_of_birth')
        user_data = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'plaintext_password': plaintext_password,
            'date_of_birth': date_of_birth
        }

        auth_service_create_account = AuthService()
        authorization_token = auth_service_create_account.register(
            user_data=user_data)

        if not authorization_token:
            response['message'] = 'Authorization token not generated'
            status = 500
        else:
            response = {
                'message': 'Creation Successful',
                'authorization_token': authorization_token
            }
            status = 200
    except ValidationError as ve:
        logger.error("Validation error %s: ", {ve})
        response['message'] = ve.messages
        status = 400
    except EmailAlreadyTaken as eat:
        logger.error("Email already taken error %s: ", {eat})
        response['message'] = "Wait, that email is already taken."
        status = 400
    except IntegrityError as int_err:
        logger.error("Integrity error %s: ", {int_err})
        response['message'] = "Wait, something went wrong on our end."
    except AssertionError as asse:
        response['message'] = f'{asse}'
        status = 400
    except DatabaseError as db_err:
        logger.error("Database error %s: ", {db_err})
        response['message'] = "Something went wrong on our end"
        status = 500
    print(response)
    return make_response(jsonify(response), status)


@auth_blueprint.route(rule='/auth/login', methods=['POST'])
def login() -> Response:
    """ This is the route for logging in. """
    login_schema = LoginSchema()
    status = 200
    if request.json is None:
        return make_response(jsonify({'message': 'Bad Request'}), 400)
    response = {'message': 'Bad Request'}

    try:
        user_data = login_schema.load(request.json)
        if not isinstance(user_data, dict):
            status = 400
            return make_response(jsonify({
                'message': 'Oops, the data you provided is not valid.'
            }), status)
        email = user_data.get('email')
        plaintext_password = user_data.get('password')
        auth_service_login = AuthService()
        authorization_token = auth_service_login.login(
            email, plaintext_password)
        if not authorization_token:
            response['message'] = 'O-oh, something went wrong on our end.'
            status = 500
        else:
            response = {
                'message': 'Yay, you are logged in!',
                'authorization_token': authorization_token
            }
    except ValidationError as ve:
        response['message'] = ve.messages
        status = 400
    except PasswordError:
        response['message'] = 'Probably you mistyped your password.'
        status = 400
    except EmailNotFound:
        response['message'] = 'Woah, we could not find an account with that email.'
        status = 404
    except DatabaseError as db_err:
        logging.error("Database error %s: ", {db_err})
        response['message'] = "Oops, something went wrong on our end. Please try again."
        status = 500
    return make_response(jsonify(response), status)
