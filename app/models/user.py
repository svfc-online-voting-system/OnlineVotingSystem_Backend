"""
    The User class contains the following columns:
            - user_id: Integer, primary key, autoincrement
            - uuid: UUID, unique, not null
            - username: String, unique, not null
            - hashed_password: String, not null
            - email: String, not null
            - date_of_birth: Date, not null
            - account_creation_date: Date, not null
            - first_name: String, not null
            - last_name: String, not null
            - is_admin: Boolean, not null, default False
            - verified_account: Boolean, not null, default False
            - verification_token: String, nullable
            - verification_expiry: Date, nullable
            - otp_secret: String, nullable
            - otp_expiry: Date, nullable
            - reset_token: String, nullable
            - reset_expiry: Date, nullable
            - deleted_at: Date, nullable
"""

# pylint: disable=R0801

from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    Date,
    select,
    update,
    Boolean,
    VARCHAR,
    BINARY,
    DateTime,
)
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy.orm import relationship
from sqlalchemy.sql import expression

from app.exception.authorization_exception import (
    EmailNotFoundException,
    PasswordResetExpiredException,
    PasswordResetLinkInvalidException,
)
from app.models.base import Base
from app.utils.engine import get_session


class User(Base):  # pylint: disable=R0903
    """
    SQLAlchemy model representing a User in the database.

    Contains user authentication fields (username, password), personal information
    (email, name, DOB), account status flags (verified, admin), and security tokens
    for password reset and account verification. Links to voting events through
    relationship.
    """

    __tablename__ = "user"

    user_id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(
        BINARY(16),
        nullable=False,
        unique=True,
    )
    username = Column(VARCHAR(45), unique=True, nullable=False)
    email = Column(VARCHAR(100), nullable=False)
    firstname = Column(VARCHAR(100), nullable=False)
    lastname = Column(VARCHAR(100), nullable=False)
    date_of_birth = Column(Date, nullable=False)
    creation_date = Column(Date, nullable=False)
    verified_account = Column(Boolean, default=expression.false(), nullable=False)
    is_admin = Column(Boolean, default=expression.false(), nullable=False)
    hashed_password = Column(VARCHAR(255), nullable=False)
    otp_secret = Column(VARCHAR(20), nullable=True)
    otp_expiry = Column(Date, nullable=True)
    reset_token = Column(VARCHAR(175), nullable=True)
    reset_expiry = Column(Date, nullable=True)
    verification_token = Column(VARCHAR(175), nullable=True)
    verification_expiry = Column(DateTime, nullable=True)
    deleted_at = Column(Date, nullable=True)

    voting_event = relationship(
        "VotingEvent",
        back_populates="user",
        cascade="save-update, merge, expunge, refresh-expire",
    )


class UserOperations:
    """
    A utility class for managing user operations in the database.

    Provides static methods for:
    - Creating new users with provided data
    - User login authentication
    - Email verification status checks
    - Email existence validation

    All methods handle database sessions and appropriate error handling for SQLAlchemy operations.
    Raises various database exceptions and EmailNotFoundException when appropriate.
    """

    @staticmethod
    def create_new_user(user_data: dict):
        """
        Creates a new user in the database using provided user data.

        Args:
            user_data (dict): Dictionary containing user details including uuid, username, email,
                            firstname, lastname, date_of_birth, creation_date, is_admin,
                            hashed_password, verification_token, verification_expiry, and
                            verified_account.

        Raises:
            DataError: If provided data is invalid
            IntegrityError: If unique constraints are violated
            DatabaseError: If database operation fails
            OperationalError: If database connection fails
        """
        session = get_session()
        try:
            new_user = User(
                uuid=user_data.get("uuid"),
                username=user_data.get("username"),
                email=user_data.get("email"),
                firstname=user_data.get("firstname"),
                lastname=user_data.get("lastname"),
                date_of_birth=user_data.get("date_of_birth"),
                creation_date=user_data.get("creation_date"),
                is_admin=user_data.get("is_admin"),
                hashed_password=user_data.get("hashed_password"),
                verification_token=user_data.get("verification_token"),
                verification_expiry=user_data.get("verification_expiry"),
                verified_account=user_data.get("verified_account"),
            )
            session.add(new_user)
            session.commit()
        except (DataError, IntegrityError, DatabaseError, OperationalError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @staticmethod
    def login(email):
        """
        Authenticates a user login attempt using their email.

        Args:
            email (str): The email address of the user attempting to login

        Returns:
            tuple: A tuple containing (hashed_password, verified_account) for the user

        Raises:
            EmailNotFoundException: If no user exists with the provided email
            OperationalError: If database connection fails
            DatabaseError: If database operation fails
        """
        session = get_session()
        try:
            user = session.execute(
                select(User.hashed_password, User.verified_account).where(
                    User.email == email
                )
            ).first()
            if user is None:
                raise EmailNotFoundException("Email not found.")
            hashed_password, verified_account = user
            return (hashed_password, verified_account)

        except (OperationalError, DatabaseError) as error:
            raise error
        finally:
            session.close()

    @staticmethod
    def is_email_verified(email):
        """
        Checks if a user's email is verified in the database.

        Args:
            email (str): The email address to check verification status for

        Returns:
            bool: True if email is verified, False otherwise

        Raises:
            EmailNotFoundException: If no user exists with the provided email
            OperationalError: If database connection fails
            DatabaseError: If database operation fails
        """
        session = get_session()
        try:
            user = session.execute(
                select(User.verified_account).where(User.email == email)
            ).first()
            if user is None:
                raise EmailNotFoundException("Email not found.")
            verified_account = user.verified_account
            return verified_account
        except (OperationalError, DatabaseError) as ex:
            raise ex
        finally:
            session.close()

    @staticmethod
    def is_email_exists(email: str) -> bool:
        """
        Checks if an email address exists in the database.

        Args:
            email (str): The email address to check

        Returns:
            bool: True if email exists, False otherwise

        Raises:
            DataError: If provided email is invalid
            IntegrityError: If database constraints are violated
            OperationalError: If database connection fails
            DatabaseError: If database operation fails
        """
        session = get_session()
        try:
            user = session.execute(
                select(User.email).filter(User.email == email)
            ).first()
            if user is not None:
                return True
            return False
        except (DataError, IntegrityError, OperationalError, DatabaseError) as e:
            raise e
        finally:
            session.close()


class PasswordOperations:
    """Class responsible for password operations like hashing, verifying, etc."""

    @staticmethod
    def verify_forgot_password_token(reset_token, new_hashed_password):
        """
        Verifies a password reset token and updates the user's password.

        Args:
            reset_token: The token to verify for password reset
            new_hashed_password: The new hashed password to set

        Returns:
            str: 'password_reset' on successful password update

        Raises:
            PasswordResetLinkInvalidException: If reset token is invalid
            PasswordResetExpiredException: If reset token has expired
            DataError: If there is a data related error
            OperationalError: If there is a database operation error
        """
        session = get_session()
        try:
            user = (
                session.execute(
                    select(User.user_id, User.reset_expiry).where(
                        User.reset_token == reset_token
                    )
                )
                .scalars()
                .first()
            )
            if user is None:
                raise PasswordResetLinkInvalidException("Invalid reset token.")
            user_id, reset_expiry = user
            if reset_expiry < datetime.now():
                session.execute(
                    update(User)
                    .where(User.user_id == user_id)
                    .values(reset_token=None, reset_expiry=None)
                )
                session.commit()
                raise PasswordResetExpiredException("Password reset link has expired.")
            return PasswordOperations.password_reset(new_hashed_password, user[0])
        except (
            PasswordResetExpiredException,
            PasswordResetLinkInvalidException,
            DataError,
            OperationalError,
        ) as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @staticmethod
    def password_reset(new_hashed_password, user_id):
        """
        Updates a user's password in the database.

        Args:
            new_hashed_password: The new hashed password to set
            user_id: The ID of the user to update

        Returns:
            str: 'password_reset' on successful password update

        Raises:
            OperationalError: If there is a database operation error
            DatabaseError: If there is a database related error
        """
        session = get_session()
        try:
            query = (
                update(User)
                .where(User.user_id == user_id)
                .values(hashed_password=new_hashed_password)
            )
            session.execute(query)
            session.commit()
            return "password_reset"
        except (OperationalError, DatabaseError, DatabaseError) as e:
            session.rollback()
            raise e
        finally:
            session.close()


class OtpOperations:
    """
    Utility class for managing OTP (One-Time Password) operations in the database.

    Contains methods for:
        - Setting OTP and expiry for a user
        - Retrieving OTP details for a user
        - Invalidating existing OTP

    All methods use SQLAlchemy session management and handle database exceptions.
    """

    @staticmethod
    def set_otp(email, otp, expiry):
        """
        Sets OTP and expiry date for a user identified by email.

        Args:
            email (str): User's email address
            otp (str): OTP value to be stored
            expiry (date): Expiry date for the OTP

        Raises:
            OperationalError: If database operation fails
            DatabaseError: If database error occurs
            DataError: If data validation fails
        """
        session = get_session()
        try:
            session.execute(
                update(User)
                .where(User.email == email)
                .values(otp_secret=otp, otp_expiry=expiry)
            )
            session.commit()
        except (OperationalError, DatabaseError, DataError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @staticmethod
    def get_otp(email):
        """
        Retrieves OTP details for a user identified by email.

        Args:
            email (str): User's email address

        Returns:
            tuple: A tuple containing (otp_secret, otp_expiry, user_id)

        Raises:
            OperationalError: If database operation fails
            DatabaseError: If database error occurs
        """
        session = get_session()
        try:
            result = session.execute(
                select(
                    User.otp_secret, User.otp_expiry, User.user_id, User.is_admin
                ).where(User.email == email)
            ).first()
            return result.otp_secret, result.otp_expiry, result.user_id, result.is_admin  # type: ignore
        except (OperationalError, DatabaseError) as exception:
            raise exception
        finally:
            session.close()

    @staticmethod
    def invalidate_otp(email: str):
        """
        Invalidates OTP for a user by setting OTP secret and expiry to None.

        Args:
            email (str): User's email address

        Raises:
            OperationalError: If database operation fails
            DatabaseError: If database error occurs
        """
        session = get_session()
        try:
            session.execute(
                update(User)
                .where(User.email == email)
                .values(otp_secret=None, otp_expiry=None)
            )
            session.commit()
        except (OperationalError, DatabaseError) as e:
            session.rollback()
            raise e
        finally:
            session.close()


class EmailVerificationOperations:
    """
    Handles email verification operations for user accounts.

    Methods:
        verify_email(token): Verifies a user's email using the provided verification token.
            Returns 'email_verified' on success or email address if token expired.
            Raises ValueError for invalid tokens.

        resend_email_verification(email, verification_expiry, verification_token):
            Updates verification token and expiry for email reverification.
            Raises EmailNotFoundException, DataError, or OperationalError on failure.
    """

    @staticmethod
    def verify_email(token):
        """
        Verifies a user's email using the provided verification token.

        Args:
            token (str): The verification token to validate.

        Returns:
            str: 'email_verified' if verification successful, or email address if token expired.

        Raises:
            ValueError: If token is invalid or does not match stored token.
            Exception: If database operation fails.
        """
        session = get_session()
        try:
            result = session.execute(
                select(
                    User.verification_expiry, User.verification_token, User.email
                ).where(User.verification_token == token)
            ).first()

            if result is None:
                raise ValueError("Invalid token.")

            verification_expiry, verification_token, email = result

            if verification_expiry < datetime.now():
                session.execute(
                    update(User)
                    .where(User.email == email)
                    .values(verification_token=None, verification_expiry=None)
                )
                session.commit()
                return email

            if verification_token != token:
                raise ValueError("Invalid token.")

            session.execute(
                update(User)
                .where(User.email == email)
                .values(
                    verified_account=True,
                    verification_token=None,
                    verification_expiry=None,
                )
            )
            session.commit()
            return "email_verified"

        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @staticmethod
    def resend_email_verification(email, verification_expiry, verification_token):
        """
        Updates verification token and expiry for a user's email reverification.

        Args:
            email (str): The email address of the user.
            verification_expiry (datetime): New expiry date for the verification token.
            verification_token (str): New verification token to be set.

        Raises:
            EmailNotFoundException: If email does not exist in database.
            DataError: If there is an error with the data format.
            OperationalError: If database operation fails.
        """
        session = get_session()
        try:
            session.execute(
                update(User)
                .where(User.email == email)
                .values(
                    verification_token=verification_token,
                    verification_expiry=verification_expiry,
                )
            )
            session.commit()
        except (EmailNotFoundException, DataError, OperationalError) as e:
            session.rollback()
            raise e
        finally:
            session.close()


class ForgotPasswordOperations:  # pylint: disable=R0903
    """
    Sends a password reset link to the user's email and updates the reset token in the database.

    Args:
        email (str): User's email address
        reset_token (str): Token for password reset verification
        reset_expiry (datetime): Expiration date for the reset token

    Returns:
        tuple: A tuple containing (reset_token, first_name)

    Raises:
        EmailNotFoundException: If email is not found in database
        DataError: If there is an error with the data format
        OperationalError: If there is a database operation error
    """

    @staticmethod
    def send_forgot_password_link(email, reset_token, reset_expiry):
        """
        Sends a password reset link to the user's email and updates the reset token in the database.

        Args:
            email (str): User's email address
            reset_token (str): Token for password reset verification
            reset_expiry (datetime): Expiration date for the reset token

        Returns:
            tuple: A tuple containing (reset_token, first_name)

        Raises:
            EmailNotFoundException: If email is not found in database
            DataError: If there is an error with the data format
            OperationalError: If there is a database operation error
        """
        session = get_session()
        try:
            result = session.execute(
                select(User.user_id, User.firstname).where(User.email == email)
            ).first()
            if result is None:
                raise EmailNotFoundException("Email not found.")
            user_id, first_name = result
            query = (
                update(User)
                .where(User.user_id == user_id)
                .values(reset_token=reset_token, reset_expiry=reset_expiry)
            )
            session.execute(query)
            session.commit()
            return reset_token, first_name
        except (EmailNotFoundException, DataError, OperationalError) as e:
            session.rollback()
            raise e
        finally:
            session.close()


class ProfileOperations:  # pylint: disable=R0903
    """Class for user profile operations."""

    @staticmethod
    def get_my_profile_settings(user_id: int):
        """Retrieves the profile settings of the user."""
        session = get_session()
        try:
            result = session.execute(
                select(
                    User.user_id,
                    User.email,
                    User.firstname,
                    User.lastname,
                    User.username,
                    User.date_of_birth,
                    User.creation_date,
                ).where(User.user_id == user_id)
            ).first()
            return {
                "user_id": result.user_id,  # type: ignore
                "email": result.email,  # type: ignore
                "first_name": result.firstname,  # type: ignore
                "last_name": result.lastname,  # type: ignore
                "username": result.username,  # type: ignore
                "date_of_birth": result.date_of_birth,  # type: ignore
                "creation_date": result.creation_date,  # type: ignore
            }
        except (EmailNotFoundException, DataError, OperationalError) as e:
            session.rollback()
            raise e
        finally:
            session.close()
