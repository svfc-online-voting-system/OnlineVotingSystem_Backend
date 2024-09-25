"""
        This is the service layer for the authentication.
        It is responsible for the login and registration of the user.
        Furthermore, it is also responsible for generating the session token.
        Additionally, it is also responsible for handling the exceptions
"""

from datetime import datetime
import logging
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from jwt import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.exc import DataError, IntegrityError, DatabaseError, OperationalError

from app.exception.email_taken import EmailAlreadyTaken
from app.exception.email_not_found_error import EmailNotFoundException
from app.exception.otp_expired import OTPExpiredException
from app.exception.otp_incorrect import OTPIncorrectException
from app.models.users import User
from app.exception.password_reset_expired import PasswordResetExpiredException
from app.exception.password_reset_link_invalid import PasswordResetLinkInvalidException

logger = logging.getLogger(__name__)


class AuthService:
    """ This class is responsible for the authentication of the user. """
    def login(self, email, plaintext_password) -> str:
        """
        This is for the login functionality. It checks first if the email
        found on the database, throws EmailNotFound if not found, otherwise
        proceed for checking the credentials.
        """
        try:
            if not User.get_user_by_email(email):
                raise EmailNotFoundException
            user_id = User.check_credentials(email, plaintext_password)
            if user_id:
                logger.info(
                    "The user with email %s: successfully logged in at %s",
                    email, datetime.now()
                )
                return User.generate_otp(email)
            return 'invalid_credentials'
        except ValueError as ve:
            raise ve
        except EmailNotFoundException as enf:
            raise enf
    @staticmethod
    def generate_session_token(email):
        """Generate a session token during call as payload."""
        return create_access_token(identity=email)
    def register(self, user_data):
        """This is the function responsible for checking necessary constrain on
                        the database if the current data in question passed"""
        try:
            row = User.get_user_by_email(user_data.get('email'))
            if row:
                raise EmailAlreadyTaken
            user = User.create_user(user_data)
            if user:
                return self.generate_session_token(user_data.get('email'))
            return None
        except EmailAlreadyTaken as eat:
            raise eat
        except IntegrityError as int_err:
            raise int_err
        except DataError as data_err:
            raise data_err
        except DatabaseError as db_err:
            raise db_err
        except Exception as e:
            raise e
    @staticmethod
    @jwt_required(locations=['cookies', 'headers'])
    def verify_token():
        """This is the function responsible for verifying the token."""
        try:
            jwt_identity = get_jwt_identity()
            logger.info("JWT Identity verified for user: %s", jwt_identity)
            return {'code': 'success', 'message': 'JWT Identity verified.'}, 200
        except ExpiredSignatureError as ese:
            raise ese
        except InvalidTokenError as ite:
            raise ite
    @staticmethod
    def generate_otp(email):
        """This is the function responsible for generating the OTP."""
        try:
            return User.generate_otp(email=email)
        except OperationalError as oe:
            raise oe
        except ValueError as ve:
            raise ve
        except EmailNotFoundException as enf:
            raise enf
        except Exception as e:
            raise e
    def verify_otp(self, email, otp):
        """This is the function responsible for verifying the OTP """
        try:
            if User.verify_otp(email=email, otp=otp):
                return self.generate_session_token(email)
            return None
        except ValueError as ve:
            raise ve
        except OperationalError as oe:
            raise oe
        except OTPExpiredException as oee:
            raise oee
        except OTPIncorrectException as oie:
            raise oie
        except EmailNotFoundException as enf:
            raise enf
        except Exception as e:
            raise e
    @staticmethod
    def send_forgot_password_link(email):
        """This is the function responsible for the forgot password."""
        try:
            return User.send_forgot_password_link(email)
        except OperationalError as oe:
            raise oe
        except ValueError as ve:
            raise ve
        except EmailNotFoundException as enf:
            raise enf
        except Exception as e:
            raise e
    @staticmethod
    def verify_forgot_password_token(toke, new_password):
        """This is the function responsible for verifying the forgot password token."""
        try:
            return User.verify_forgot_password_token(toke, new_password)
        except OperationalError as oe:
            raise oe
        except ValueError as ve:
            raise ve
        except PasswordResetExpiredException as pree:
            raise pree
        except PasswordResetLinkInvalidException as prli:
            raise prli
