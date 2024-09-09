from sqlite3 import IntegrityError
from app.exception.email_not_found import EmailNotFound
from app.exception.email_taken import EmailAlreadyTaken
from app.models.users import User
from flask_jwt_extended import create_access_token
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class AuthService:
	
	def login(self, email, plaintext_password):
		"""This is for the login functionality. It checks first if the email found on the database, throws
		EmailNotFound if not found, otherwise proceed for checking the credentials."""
		if not User.get_user_by_email(email):
			raise EmailNotFound
		
		user_id = User.check_credentials(email, plaintext_password)
		if user_id:
			# logger.info(f"The user with email {email} successfully logged in at {datetime.now()}")
			return self.generate_session_token(user_id, email)
		
		return None
	
	@staticmethod
	def generate_session_token(user_id, email):
		"""Generate a session token during call as payload."""
		return create_access_token(identity={'user_id': user_id, 'email': email})
	
	@classmethod
	def register(cls, first_name, last_name, email, plaintext_password, date_of_birth):
		"""This is the function responsible for checking necessary constrain on the database if the current data in
		question passed"""
		try:
			if User.get_user_by_email(email):
				raise EmailAlreadyTaken
			user = User.create_user(first_name, last_name, email, plaintext_password, date_of_birth)
			if user:
				logger.info(f"The new user with email: {email} successfully created an account at {datetime.now()}")
				return cls.generate_session_token(user.user_id, user.email)
		except EmailAlreadyTaken as eat:
			raise eat
		except IntegrityError as int_err:
			raise int_err
		except Exception as e:
			raise e
