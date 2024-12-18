"""Tests for the User model."""

# pylint: disable=redefined-outer-name
# pylint: disable=C0103

from base64 import urlsafe_b64encode
from datetime import datetime, timedelta
from os import urandom
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from bcrypt import gensalt, hashpw
from sqlalchemy.exc import IntegrityError

from app.exception.authorization_exception import EmailNotFoundException
from app.models.user import User, UserOperations


@pytest.fixture
def mock_session():
    """Mock the session object."""
    with patch("app.models.user.get_session") as mock:
        session = Mock()
        mock.return_value = session
        yield session


@pytest.fixture
def valid_user_data():
    """Represents a valid user data."""
    hashed_password = (
        hashpw("hashedpassword123".encode("utf-8"), gensalt(rounds=16))
    ).decode("utf-8")
    verification_token = urlsafe_b64encode(urandom(128)).decode("utf-8").rstrip("=")
    return {
        "uuid": uuid4().bytes,
        "username": "testuser",
        "email": "test@example.com",
        "firstname": "Test",
        "lastname": "User",
        "date_of_birth": datetime(1990, 1, 1).date(),
        "creation_date": datetime.now().date(),
        "verified_account": False,
        "is_admin": False,
        "hashed_password": hashed_password,
        "otp_secret": None,
        "otp_expiry": None,
        "reset_token": None,
        "reset_expiry": None,
        "verification_token": verification_token,
        "verification_expiry": (datetime.now() + timedelta(days=1)).date(),
    }


# noinspection PyTypeHints,SqlNoDataSourceInspection
class TestUserOperation:
    """Test for user operations."""

    def test_create_user_when_input_valid(
        self, mock_session, valid_user_data
    ):  # pylint: disable=C0103
        """Test creating a new user with valid data."""
        mock_session.commit = Mock()
        mock_user = Mock()
        mock_user.user_id = 1
        mock_session.add.return_value = None

        def side_effect(user):
            user.user_id = 1

        mock_session.add.side_effect = side_effect

        UserOperations.create_new_user(valid_user_data)

        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

        user_obj = mock_session.add.call_args[0][0]
        assert isinstance(user_obj, User)
        assert user_obj.username == valid_user_data["username"]
        assert user_obj.email == valid_user_data["email"]
        assert user_obj.firstname == valid_user_data["firstname"]
        assert user_obj.lastname == valid_user_data["lastname"]
        assert user_obj.date_of_birth == valid_user_data["date_of_birth"]
        assert user_obj.creation_date == valid_user_data["creation_date"]
        assert user_obj.is_admin == valid_user_data["is_admin"]
        assert user_obj.hashed_password == valid_user_data["hashed_password"]
        assert user_obj.otp_secret == valid_user_data["otp_secret"]
        assert user_obj.otp_expiry == valid_user_data["otp_expiry"]
        assert user_obj.reset_token == valid_user_data["reset_token"]
        assert user_obj.reset_expiry == valid_user_data["reset_expiry"]
        assert user_obj.verification_token == valid_user_data["verification_token"]
        assert user_obj.verification_expiry == valid_user_data["verification_expiry"]
        assert user_obj.verified_account == valid_user_data["verified_account"]
        assert isinstance(user_obj.uuid, bytes)

    def test_raise_integrity_error_email_taken(
        self, mock_session, valid_user_data
    ):  # pylint: disable=C0103
        """Test creating a new user with an email that is already taken."""
        mock_session.add = Mock(
            side_effect=IntegrityError("statement", "params", "orig")  # type: ignore
        )  # type: ignore
        with pytest.raises(IntegrityError):
            UserOperations.create_new_user(valid_user_data)

    def test_raise_integrity_error_username_taken(
        self, mock_session, valid_user_data
    ):  # pylint: disable=C0103
        """Test creating a new user with a username that is already taken."""
        mock_session.add = Mock(
            side_effect=IntegrityError("statement", "params", "orig")  # type: ignore
        )  # type: ignore
        with pytest.raises(IntegrityError):
            UserOperations.create_new_user(valid_user_data)

    @pytest.mark.parametrize(
        "missing_field",
        [
            "username",
            "email",
            "firstname",
            "lastname",
            "date_of_birth",
            "creation_date",
            "salt",
            "hashed_password",
            "otp_secret",
            "otp_expiry",
            "reset_token",
            "reset_expiry",
            "verification_token",
            "verification_expiry",
            "verified_account",
            "uuid",
        ],
    )
    def test_raise_integrity_error_required_field(
        self, mock_session, valid_user_data, missing_field
    ):  # pylint: disable=C0103
        """Test creating a new user with a missing required field."""
        # Arrange
        valid_user_data[missing_field] = None
        error_message = f'null value in column "{missing_field}" of relation "user" violates not-null constraint'
        mock_session.commit.side_effect = IntegrityError(
            statement="INSERT INTO user ...", params={}, orig=Exception(error_message)
        )

        with pytest.raises(IntegrityError) as exc_info:
            UserOperations.create_new_user(valid_user_data)

        assert "violates not-null constraint" in str(exc_info.value)
        mock_session.rollback.assert_called_once()

    def test_return_pw_verified_user_exists(self, mock_session, valid_user_data):
        """Test getting the hashed password and salt for a user that exists."""
        # Setup mock to return tuple instead of User object
        mock_session.execute.return_value.first.return_value = (
            valid_user_data["hashed_password"],
            valid_user_data["verified_account"],
        )

        # Call login method
        result = UserOperations.login(valid_user_data["email"])
        hashed_password, verified_account = result

        # Assert results
        assert hashed_password == valid_user_data["hashed_password"]
        assert verified_account == valid_user_data["verified_account"]

    def test_return_email_not_found_exception_not_exist(
        self, mock_session
    ):  # pylint: disable=C0103
        """Test getting the hashed password and salt for a user that does not exist."""
        mock_session.execute.return_value.first.return_value = None

        with pytest.raises(EmailNotFoundException) as exc_info:
            UserOperations.login("some_arbitrary_email@example.com")

        assert "Email not found." in str(exc_info.value)

    def test_return_false_email_not_verified(
        self, mock_session, valid_user_data
    ):  # pylint: disable=C0103
        """Test checking if a user is verified."""
        mock_session.execute.return_value.first.return_value = User(**valid_user_data)

        is_verified = UserOperations.is_email_verified(valid_user_data["email"])

        assert is_verified is False

    def test_return_true_email_verified(
        self, mock_session, valid_user_data
    ):  # pylint: disable=C0103
        """Test checking if a user is verified."""
        valid_user_data["verified_account"] = True
        mock_session.execute.return_value.first.return_value = User(**valid_user_data)

        is_verified = UserOperations.is_email_verified(valid_user_data["email"])

        assert is_verified is True

    def test_non_existent_email_raises_exception(
        self, mock_session
    ):  # pylint: disable=C0103
        """Test checking if a user is verified."""
        mock_session.execute.return_value.first.return_value = None

        with pytest.raises(EmailNotFoundException, match="Email not found."):
            UserOperations.is_email_verified("nonexistent@example.com")

    def test_return_true_email_exists(
        self, mock_session, valid_user_data
    ):  # pylint: disable=C0103
        """Test checking if an email exists."""
        mock_session.query.return_value.first.return_value = User(**valid_user_data)

        email_exists = UserOperations.is_email_exists(valid_user_data["email"])

        assert email_exists is True

    def test_return_false_email_not_exist(self, mock_session):  # pylint: disable=C0103
        """Test checking if an email exists."""
        mock_session.execute.return_value.first.return_value = None

        email_exists = UserOperations.is_email_exists("test_email@someone.com")
        assert email_exists is False


class TestPasswordOperations:  # pylint: disable=R0903
    """Test for password operations."""


class TestOTPOperations:  # pylint: disable=R0903
    """Test for OTP operations."""


class TestEmailVerificationOperations:  # pylint: disable=R0903
    """Test for email verification operations."""


class TestForgotPasswordOperations:  # pylint: disable=R0903
    """Test for forgot password operations."""
