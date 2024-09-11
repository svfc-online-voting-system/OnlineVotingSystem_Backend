"""
	This file contains the PasswordError class which is a custom exception
	class that will be thrown if the user does have an email registered
	but with the wrong password.
"""
from app.exception.custom_exception import CustomException


class PasswordError(CustomException):
    """This will be thrown if the user does have an email registered but with the wrong password."""

    def __init__(self, message="User not found."):
        self.message = message
        super().__init__(message)
