"""
            This exception files contains exceptions that are
            related to the authorization of the user.
    """
from app.exception.custom_exception import CustomException


class EmailNotFoundException(CustomException):
    """
        This error is for error that the user tries to log in with an email that
        doesn't exist on the database.
    """
    def __init__(self, message="Email not found."):
        self.message = message
        super().__init__(message)


class EmailAlreadyTaken(CustomException):
    """
        This is for error that will be raised when the user creates an account
        with an email that is already taken. A bit redundant, but it will be
        beneficial for custom errors rather than SQL Generic Errors on
        Primary keys. Additionally, this approach will ultimately lay off the
        exception on the API Level, further reducing the load for database.
    """
    def __init__(self, message="Email already taken."):
        self.message = message
        super().__init__(message)


class PasswordResetExpiredException(CustomException):
    """
        This is for error that will be raised when the password reset link has expired.
    """
    def __init__(self, message="Password reset link has expired."):
        self.message = message
        super().__init__(message)


class PasswordResetLinkInvalidException(CustomException):
    """
        This is for error that will be raised when the password reset link is invalid.
    """
    def __init__(self, message="Password reset link is invalid."):
        self.message = message
        super().__init__(message)


class OTPIncorrectException(CustomException):
    """
        This is for error that will be raised when the OTP is incorrect.
    """
    def __init__(self, message="OTP is incorrect."):
        self.message = message
        super().__init__(message)


class OTPExpiredException(CustomException):
    """
        This is for error that will be raised when the OTP has expired.
    """
    def __init__(self, message="OTP has expired."):
        self.message = message
        super().__init__(message)


class AccountNotVerifiedException(CustomException):
    """
        This error is for the user that tries to log in with an email that
        is not yet verified.
    """
    def __init__(self, message="Account not verified."):
        self.message = message
        super().__init__(message)


class PasswordIncorrectException(CustomException):
    """
        This error is for the user that tries to log in with a password that
        is incorrect.
    """
    def __init__(self, message="Password incorrect."):
        self.message = message
        super().__init__(message)
