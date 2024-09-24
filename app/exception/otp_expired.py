"""
This error will be raised when the OTP has expired.
This will be beneficial since we're using time based OTPs.
"""
from app.exception.custom_exception import CustomException


class OTPExpiredException(CustomException):
    """
        This is for error that will be raised when the OTP has expired.
    """
    def __init__(self, message="OTP has expired."):
        self.message = message
        super().__init__(message)
