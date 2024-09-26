"""
This module is responsible for handling the password error exception.
"""
from app.exception.custom_exception import CustomException


class PasswordErrorException(CustomException):
    """This class is responsible for handling the password error exception."""

    def __init__(self, message="Password is incorrect."):
        self.message = message
        super().__init__(message)
