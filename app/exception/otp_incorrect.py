"""
This is for error that will be raised when the OTP is incorrect."""
from app.exception.custom_exception import CustomException


class OTPIncorrectException(CustomException):
    """
        This is for error that will be raised when the OTP is incorrect.
    """
    def __init__(self, message="OTP is incorrect."):
        self.message = message
        super().__init__(message)
