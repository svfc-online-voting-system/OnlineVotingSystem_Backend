"""This module contains the error handlers for the authentication module."""

from app.exception.authorization_exception import (
    EmailNotFoundException,
    OTPExpiredException,
    OTPIncorrectException,
    PasswordResetExpiredException,
    PasswordResetLinkInvalidException,
    EmailAlreadyTaken,
    PasswordIncorrectException,
    AccountNotVerifiedException,
)
from app.utils.error_handlers.base_error_handler import handle_error


def handle_account_not_verified_exception(error):
    """This function handles account not verified exceptions."""
    if isinstance(error, AccountNotVerifiedException):
        return handle_error(error, 401, "account_not_verified", "Account not verified.")
    raise error


def handle_email_not_found(error):
    """This function handles email not found exceptions."""
    if isinstance(error, EmailNotFoundException):
        return handle_error(error, 404, "email_not_found", "Email not found.")
    raise error


def handle_otp_expired_exception(error):
    """This function handles OTP expired exceptions."""
    if isinstance(error, OTPExpiredException):
        return handle_error(error, 400, "otp_expired", "OTP has expired.")
    raise error


def handle_otp_incorrect_exception(error):
    """This function handles OTP incorrect exceptions."""
    if isinstance(error, OTPIncorrectException):
        return handle_error(error, 400, "otp_incorrect", "OTP is incorrect.")
    raise error


def handle_password_reset_expired_exception(error):
    """This function handles password reset expired exceptions."""
    if isinstance(error, PasswordResetExpiredException):
        return handle_error(
            error, 400, "password_reset_expired", "Password reset link has expired."
        )
    raise error


def handle_password_reset_link_invalid_exception(error):
    """This function handles password reset link invalid exceptions."""
    if isinstance(error, PasswordResetLinkInvalidException):
        return handle_error(
            error, 400, "password_reset_link_invalid", "Password reset link is invalid."
        )
    raise error


def handle_password_incorrect_exception(error):
    """This function handles password errors."""
    if isinstance(error, PasswordIncorrectException):
        return handle_error(error, 400, "password_error", "Invalid credentials.")
    raise error


def handle_email_already_taken(error):
    """This function handles email already taken errors."""
    if isinstance(error, EmailAlreadyTaken):
        return handle_error(error, 400, "email_already_taken", "Email already taken.")
    raise error
