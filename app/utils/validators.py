from app.exception.required_error import RequiredError
from validate_email import validate_email


def validate_password(password: str) -> None:
	assert len(password) > 8, "Password is too short. 8 character alphanumeric required"
	assert password.isalnum(), "Password requires alphanumeric"


def check_required_fields(*args) -> None:
	if any(v is None or v == '' for v in args):
		raise RequiredError("All fields are required.")


def is_valid_email(email: str) -> None:
	assert validate_email(email, verify=True), "Email is invalid."

