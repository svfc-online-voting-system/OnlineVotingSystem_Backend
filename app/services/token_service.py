""" This module contains the TokenService class. """

from flask_jwt_extended import create_access_token, create_refresh_token

class TokenService:
    """ This class provides methods for generating JWT tokens. """
    @staticmethod
    def generate_jwt_csrf_token(email, user_id):  # pylint: disable=C0116
        access_token = create_access_token(
            identity={'email': email, 'user_id': user_id},
            fresh=True,
        )
        refresh_token = create_refresh_token(
            identity={'email': email, 'user_id': user_id}
        )
        return access_token, refresh_token
