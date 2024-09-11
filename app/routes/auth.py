"""
        This module contains the routes for the authentication of users.
"""

from sqlite3 import IntegrityError, DatabaseError
import logging
from flask import Blueprint, request, jsonify, Response
from app.exception.password_error import PasswordError
from app.exception.email_not_found import EmailNotFound
from app.exception.required_error import RequiredError
from app.utils.validators import validate_password
from app.services.auth_service import AuthService

logger = logging.getLogger(name=__name__)
auth_blueprint = Blueprint('auth', __name__)
auth_service = AuthService()


@auth_blueprint.route(rule='/auth/create-account', methods=['POST'])
def create_account() -> Response:
    """ This is the route for creating an account. """
    registration_data = request.json
    response = {'status': 400, 'message': 'Bad Request'}

    if registration_data is None:
        return jsonify(response)

    first_name = str(object=registration_data.get('firstName'))
    last_name = str(object=registration_data.get('lastName'))
    email = str(object=registration_data.get('email'))
    plaintext_password = str(object=registration_data.get('password'))
    date_of_birth = registration_data.get('dateOfBirth')

    user_data = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'plaintext_password': plaintext_password,
        'date_of_birth': date_of_birth
    }

    try:
        validate_password(plaintext_password)
        if any(
            v is None
            for v in [
                first_name,
                last_name,
                email,
                plaintext_password,
                date_of_birth]
        ):
            raise RequiredError

        auth_service_create_account = AuthService()
        authorization_token = auth_service_create_account.register(
            user_data=user_data)

        if not authorization_token:
            response['message'] = 'Authorization token not generated'
        else:
            response = {
                'status': 200,
                'message': 'Creation Successful',
                'authorization_token': authorization_token
            }

    except IntegrityError as int_err:
        logger.error("Integrity error %s: ", {int_err})
        response['message'] = "An account with that email already exists."

    except RequiredError as re:
        logger.error("Required error %s: ", {re})
        response['message'] = "All fields are required, please double check."

    except AssertionError as asse:
        response['message'] = f'{asse}'

    except DatabaseError as db_err:
        logger.error("Database error %s: ", {db_err})
        response['message'] = "Something went wrong on our end"

    return jsonify(response)



@auth_blueprint.route(rule='/auth/login', methods=['POST'])
def login() -> Response:
    """ This is the route for logging in. """
    user_data = request.json
    response = {'status': 400, 'message': 'Bad Request'} # Default response
    if user_data is None:
        return jsonify({'status': 400, 'message': 'Bad Request'})
    email = user_data.get('email')
    plaintext_password = user_data.get('password')
    try:
        auth_service_login = AuthService()
        authorization_token = auth_service_login.login(
            email, plaintext_password)
        if not authorization_token:
            response['message'] = 'Something went wrong on our end'
        else:
            response = {
                'status': 200,
                'message': 'Login Successful',
                'authorization_token': authorization_token
            }
    except PasswordError:
        response['message'] = 'Password Error'
    except EmailNotFound:
        response['message'] = 'Email Not Found'
    except DatabaseError as db_err:
        logging.error("Database error %s: ", {db_err})
        response['message'] = "Something went wrong on our end"
    return jsonify(response)
