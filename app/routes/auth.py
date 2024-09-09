from sqlite3 import IntegrityError
from app.exception.password_error import PasswordError
from app.exception.email_not_found import EmailNotFound
from app.exception.required_error import RequiredError
from flask import Blueprint, request, jsonify
from app.utils.validators import validate_password
from app.services.auth_service import AuthService
import logging

logger = logging.getLogger(name=__name__)
auth_blueprint = Blueprint('auth', __name__)
auth_service = AuthService()


@auth_blueprint.route('/auth/create-account', methods=['POST'])
def create_account():
	registration_data = request.json
	first_name = str(registration_data.get('firstName'))
	last_name = str(registration_data.get('lastName'))
	email = str(registration_data.get('email'))
	plaintext_password = str(registration_data.get('password'))
	date_of_birth = registration_data.get('dateOfBirth')
	try:
		validate_password(plaintext_password)
		if any(v is None for v in [first_name, last_name, email, plaintext_password, date_of_birth]):
			raise RequiredError
		authorization_token = AuthService.register(
			first_name, last_name, email, plaintext_password, date_of_birth)
		if authorization_token:
			return jsonify({'status': 200, 'message': 'Creation Successful', 'authorization_token': authorization_token})
	except IntegrityError as int_err:
		logger.error(f"Integrity error {int_err}")
		return jsonify({'status': 400, 'message': f'{int_err}'})
	except RequiredError as re:
		return jsonify({'status': 400, 'message': f"{re}"})
	except AssertionError as asse:
		return jsonify({'status': 400, 'message': f"{asse}"})
	except Exception as e:
		logger.error(f"{e}")
		return jsonify({'status': 400, 'message': f"{e}"})
		
	
@auth_blueprint.route('/auth/login', methods=['POST'])
def login():
	user_data = request.json
	email = user_data.get('email')
	plaintext_password = user_data.get('password')
	try:
		authorization_token = AuthService.login(email, email, plaintext_password)
		if authorization_token:
			return jsonify({'status': 200, 'message': 'Login Successful', 'authorization_token': authorization_token})
	except PasswordError:
		return jsonify({'status': 401, 'message': 'Password Error'})
	except EmailNotFound:
		return jsonify({'status': 404, 'message': 'Email Not Found'})
	except Exception as e:
		return jsonify({'status': 500, 'message': f'Server Error {e}'})
