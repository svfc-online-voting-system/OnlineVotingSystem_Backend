"""
	This module contains functions that validate user input.
"""
from validate_email import validate_email
from app.exception.required_error import RequiredError


def validate_password(password: str) -> None:
    """ Validates the password. """
    assert len(
        password) > 8, "Password is too short. 8 character alphanumeric required"
    assert password.isalnum(), "Password requires alphanumeric"


def check_required_fields(*args) -> None:
    """ This will check if all fields are filled. """
    if any(v is None or v == '' for v in args):
        raise RequiredError("All fields are required.")


def is_valid_email(email: str) -> None:
    """ This will check if the email is valid. """
    assert validate_email(email, verify=True), "Email is invalid."
