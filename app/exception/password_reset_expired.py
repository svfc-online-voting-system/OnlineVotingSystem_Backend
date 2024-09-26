"""
    This is for error that will be raised when the password reset link has expired.
"""
from app.exception.custom_exception import CustomException


class PasswordResetExpiredException(CustomException):
    """
        This is for error that will be raised when the password reset link has expired.
    """
    def __init__(self, message="Password reset link has expired."):
        self.message = message
        super().__init__(message)
