"""
    This is for error that will be raised when the password reset link is invalid.
"""
from app.exception.custom_exception import CustomException


class PasswordResetLinkInvalidException(CustomException):
    """
        This is for error that will be raised when the password reset link is invalid.
    """
    def __init__(self, message="Password reset link is invalid."):
        self.message = message
        super().__init__(message)
