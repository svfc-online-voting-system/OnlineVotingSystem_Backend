"""
        This is the service layer for the authentication.
        It is responsible for the login and registration of the user.
        Furthermore, it is also responsible for generating the session token.
        Additionally, it is also responsible for handling the exceptions
"""

from datetime import datetime
from sqlite3 import IntegrityError, DatabaseError
import logging
from flask_jwt_extended import create_access_token
from app.exception.email_taken import EmailAlreadyTaken
from app.exception.email_not_found import EmailNotFound
from app.models.users import User

logger = logging.getLogger(__name__)


class AuthService:
    """ This class is responsible for the authentication of the user. """

    def login(self, email, plaintext_password):
        """
        This is for the login functionality. It checks first if the email
        found on the database, throws EmailNotFound if not found, otherwise
        proceed for checking the credentials.
        """
        if not User.get_user_by_email(email):
            raise EmailNotFound

        user_id = User.check_credentials(email, plaintext_password)
        if user_id:
            logger.info(
                "The user with email %s: successfully logged in at %s",
                email, datetime.now()
            )
            return self.generate_session_token(email)
        return None

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
        except DatabaseError as db_err:
            raise db_err
        except AssertionError as ae:
            raise ae
        except Exception as e:
            raise e
