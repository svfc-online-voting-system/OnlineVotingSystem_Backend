"""
    This is the service layer for the authentication.
    It is responsible for the login and registration of the user.
    Furthermore, it is also responsible for generating the session token.
    Additionally, it is also responsible for handling the exceptions
"""
import os
from datetime import datetime
import base64
import logging
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import bcrypt
from jwt import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.exc import DataError, IntegrityError, DatabaseError, OperationalError

from app.exception.authorization_exception import (EmailAlreadyTaken, EmailNotFoundException,
                                                   OTPExpiredException,
                                                   OTPIncorrectException,
                                                   PasswordResetExpiredException,
                                                   PasswordResetLinkInvalidException,
                                                   AccountNotVerifiedException)
from app.models.user_profile import UserProfile
from app.models.users import User

logger = logging.getLogger(__name__)


class AuthService:
    """ This class is responsible for the authentication of the user. """
    def register(self, user_data):
        """
            This is the function responsible for checking necessary
            constrain on the database if the current data in question passed
        """
        try:
            salt = bcrypt.gensalt(rounds=16).decode('utf=8')
            hashed_password = bcrypt.hashpw(user_data.get('password').encode(
                'utf-8'), salt.encode('utf-8')).decode('utf-8')
            email_verification_token = base64.b64encode(os.urandom(128)).decode('utf-8')
            is_email_exists = UserProfile.email_exists(user_data.get('email'))
            user_auth_data = {
                'salt': salt,
                'password': hashed_password,
                'email_verification_token': email_verification_token
            }
            user_profile_data = {
                'username': user_data.get('email').split('@')[0],
                'email': user_data.get('email'),
                'first_name': user_data.get('first_name').capitalize(),
                'last_name': user_data.get('last_name').capitalize(),
                'date_of_birth': user_data.get('date_of_birth'),
                'account_creation_date': datetime.now(),
                'email_verification_token': email_verification_token
            }
            if is_email_exists:
                raise EmailAlreadyTaken('Email already taken.')
            user_id = User.create_new_user(user_auth_data)
            user_profile_data['user_id'] = user_id
            UserProfile.add_new_profile_data(user_profile_data)
            return 'success'
        except EmailAlreadyTaken as e:
            raise e
        except (IntegrityError, DataError, DatabaseError, OperationalError) as ex:
            raise ex
    @staticmethod
    def login(email, plaintext_password) -> str:
        """
        This is for the login functionality. It checks first if the email
        found on the database, throws EmailNotFound if not found, otherwise
        proceed for checking the credentials.
        """
        try:
            if not User.get_user_by_email(email):
                raise EmailNotFoundException('Email not found.')
            if not User.is_account_verified(email):
                raise AccountNotVerifiedException('Account not verified.')
            user_id = User.check_credentials(email, plaintext_password)
            if user_id:
                logger.info(
                    "The user with email %s: successfully logged in at %s",
                    email, datetime.now()
                )
                return User.generate_otp(email)
            return 'invalid_credentials'
        except (OperationalError, ValueError,
                EmailNotFoundException,
                AccountNotVerifiedException) as e:
            raise e
    @staticmethod
    def generate_session_token(email):
        """Generate a session token during call as payload."""
        return create_access_token(identity=email)

    @staticmethod
    @jwt_required(locations=['cookies', 'headers'])
    def verify_token():
        """This is the function responsible for verifying the token."""
        try:
            jwt_identity = get_jwt_identity()
            logger.info("JWT Identity verified for user: %s", jwt_identity)
            return {'code': 'success', 'message': 'JWT Identity verified.'}, 200
        except (ExpiredSignatureError, InvalidTokenError) as e:
            raise e
    @staticmethod
    def generate_otp(email):
        """This is the function responsible for generating the OTP."""
        try:
            return User.generate_otp(email=email)
        except (OperationalError, ValueError, EmailNotFoundException) as e:
            raise e
    def verify_otp(self, email, otp):
        """This is the function responsible for verifying the OTP """
        try:
            if User.verify_otp(email=email, otp=otp):
                return self.generate_session_token(email)
            return None
        except (OperationalError, ValueError, OTPExpiredException, OTPIncorrectException,
                EmailNotFoundException) as e:
            raise e
    @staticmethod
    def send_forgot_password_link(email):
        """This is the function responsible for the forgot password."""
        try:
            return User.send_forgot_password_link(email)
        except (EmailNotFoundException, ValueError, OperationalError) as e:
            raise e
    @staticmethod
    def verify_forgot_password_token(toke, new_password):
        """This is the function responsible for verifying the forgot password token."""
        try:
            return User.verify_forgot_password_token(toke, new_password)
        except (PasswordResetExpiredException, PasswordResetLinkInvalidException,
                ValueError, DataError, OperationalError) as e:
            raise e
