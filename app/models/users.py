"""
	Description:
		This module contains the User class which is a SQLAlchemy model for the
		users table in the database.

	Extended Description:
		The User class contains the following columns:
				- user_id: Integer, primary key, autoincrement
				- username: String, unique, not null
				- salt: String, not null
				- hashed_password: String, not null
				- email: String, not null
				- date_of_birth: Date, not null
				- account_creation_date: Date, not null
				- first_name: String, not null
				- last_name: String, not null

		The User class also contains the following class methods:
				- create_user: Creates a new user in the database.
				- get_user_by_email: Retrieves a user from the database by email.
				- check_credentials: Checks the credentials of a user.

		The User class also creates the users table in the database.

    Returns:
            user: User
"""
import base64
import hashlib
import urllib.parse
from datetime import datetime, timedelta
from os import getenv, urandom
import time

import bcrypt
import pyotp

from sqlalchemy import Column, Integer, String, Date, select, update, Boolean
from sqlalchemy.orm import relationship, joinedload
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy.sql import expression
from sqlalchemy.sql.operators import or_

from app.models.profiles import Profiles
from app.utils.email_utility import send_mail
from app.utils.engine import get_session, get_engine
from app.exception.authorization_exception import (EmailNotFoundException, OTPExpiredException,
                                                   OTPIncorrectException,
                                                   PasswordResetExpiredException,
                                                   PasswordResetLinkInvalidException)
from app.models.base import Base


class Users(Base):
    """Class representing a User in the database."""
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    salt = Column(String(45), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    otp_secret = Column(String(20), nullable=True)
    otp_expiry = Column(Date, nullable=True)
    reset_token = Column(String(175), nullable=True)
    reset_expiry = Column(Date, nullable=True)
    verified_account = Column(
        Boolean, default=expression.false(), nullable=False)
    verification_token = Column(String(175), nullable=True)
    verification_expiry = Column(Date, nullable=True)
    profiles = relationship("Profiles",
                           back_populates="users",
                           uselist=False, cascade="all, delete-orphan")
    FRONT_END_FORGOT_PASSWORD_URL = getenv(
        'LOCAL_FRONTEND_URL') + '/reset-password/'

    @classmethod
    def create_new_user(cls, user_data: dict):
        """Create a new user in the database."""
        session = get_session()
        # pylint: disable=R0801
        try:
            new_user = cls(
                salt=user_data.get("salt"),
                hashed_password=user_data.get("password"),
                verification_token=user_data.get("email_verification_token"),
                verification_expiry=datetime.now() + timedelta(minutes=2880),
                verified_account=False
            )
            session.add(new_user)
            session.commit()
            return new_user.user_id
        except (DataError, IntegrityError, OperationalError, DatabaseError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @classmethod
    def login(cls, email):
        """Login a user."""
        session = get_session()
        try:
            user_with_profile = (session.query(cls)
                                .options(joinedload(cls.profiles))
                                .join(Profiles).filter(
                Profiles.email == email
            ).first())
            if user_with_profile:
                email = user_with_profile.profile.email
                password = user_with_profile.hashed_password
                salt = user_with_profile.salt
                return {
                    'email': email,
                    'password': password,
                    'salt': salt
                }
            return None, None, None
        except OperationalError as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @classmethod
    def generate_otp(cls, email) -> str:
        """
            Function responsible for generating OTP Code
            that also verifies if the email does exist.
        """
        session = get_session()
        try:
            seed = f"{getenv('TOTP_SECRET_KEY')}{int(time.time())}"
            seven_digit_otp = pyotp.TOTP(base64.b32encode(bytes.fromhex(seed))
                                         .decode('UTF-8'),
                                         digits=7, interval=300, digest=hashlib.sha256).now()
            otp_expiry: datetime = datetime.now() + timedelta(minutes=5)
            subject = "Your OTP Verification code"
            message = \
                f"Here's your OTP Code: {
                    seven_digit_otp}. Use this to get access to your account."
            query = (
                update(Users)
                .where(Users.user_id == Profiles.user_id)
                .where(Profiles.email == email)
                .values(otp_secret=seven_digit_otp, otp_expiry=otp_expiry)
            )
            session.execute(query)
            send_mail(email=email, message=message, subject=subject)
            session.commit()
            return 'otp_sent'
        except (OperationalError, DatabaseError, DataError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @classmethod
    def is_email_verified(cls, email):
        """Check if an email is verified."""
        session = get_session()
        try:
            user = session.query(cls).options(joinedload(cls.profiles)).join(Profiles).filter(
                Profiles.email == email
            ).first()
            return bool(user.verified_account)
        except OperationalError as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @classmethod
    def verify_forgot_password_token(cls, reset_token, new_password) -> str:
        """
        Function responsible for verifying the reset token.
        """
        session = get_session()
        try:
            user = session.execute(select(Users.user_id, Users.reset_expiry)
                                   .where(Users.reset_token == reset_token)).first()
            if user is None:
                raise PasswordResetLinkInvalidException("Invalid reset token.")
            if user[1] < datetime.now():
                query = (
                    update(Users)
                    .where(Users.user_id == user[0])
                    .where(Profiles.user_id == user[0])
                    .values(reset_token=None, reset_expiry=None)
                )
                session.execute(query)
                session.commit()
                raise PasswordResetExpiredException(
                    "Password reset link has expired.")
            return cls.password_reset(new_password, user[0])
        except (PasswordResetExpiredException, PasswordResetLinkInvalidException,
                DataError, OperationalError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @classmethod
    def password_reset(cls, new_password, user_id):
        """
        Function responsible for resetting the password.
        """
        session = get_session()
        try:
            salt = bcrypt.gensalt(rounds=16).decode('utf=8')
            hashed_password = (bcrypt.hashpw(new_password.encode('utf-8'), salt.encode('utf-8'))
                               .decode('utf-8'))
            query = (
                update(Users)
                .where(Users.user_id == user_id)
                .values(salt=salt, hashed_password=hashed_password)
            )
            session.execute(query)
            session.commit()
            return 'password_reset'
        except (OperationalError, DatabaseError, DatabaseError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @classmethod
    def verify_otp(cls, email, otp) -> str:
        """Function responsible for verifying the OTP Code."""
        session = get_session()
        try:
            user_otp_query = session.execute(
                select(Users.otp_secret, Users.otp_expiry)
                .where(Users.user_id == Profiles.user_id)
                .where(Profiles.email == email)
            ).first()
            user_otp_secret, user_otp_expiry = user_otp_query
            session.execute(user_otp_query).first()
            if user_otp_secret is None or user_otp_expiry is None:
                raise OTPExpiredException("OTP has expired.")
            if user_otp_expiry < datetime.now():
                query = (
                    update(Users)
                    .where(Users.user_id == Profiles.user_id)
                    .where(Profiles.email == email)
                    .values(otp_secret=None, otp_expiry=None)
                )
                session.execute(query)
                session.commit()
                raise OTPExpiredException("OTP has expired.")
            if int(user_otp_query[0]) != int(otp):
                raise OTPIncorrectException("Incorrect OTP.")
            query = (
                update(Users)
                .where(Users.user_id == Profiles.user_id)
                .where(Profiles.email == email)
                .values(otp_secret=None, otp_expiry=None)
            )
            session.execute(query)
            session.commit()
            return 'otp_verified'
        except (OperationalError, OTPExpiredException, OTPIncorrectException,
                EmailNotFoundException) as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @classmethod
    def is_account_verified(cls, email) -> bool:
        """
            Function responsible for checking if the account is verified.
        """
        session = get_session()
        try:
            result = session.query(select(Users.verified_account)
                                   .where(Users.user_id == Profiles.user_id)
                                   .where(Profiles.email == email)).first()
            is_verified = result
            if is_verified:
                return True
            return False
        except OperationalError as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @classmethod
    def verify_email(cls, token):
        """ Function responsible for verifying the email."""
        session = get_session()
        try:
            cleaned_token = urllib.parse.unquote(token).replace(" ", "+")
            user = session.query(cls).options(joinedload(cls.profiles)).join(Profiles).filter(
                or_(
                    cls.verification_token == cleaned_token,
                    cls.verification_token == token
                )
            ).first()
            if user is None:
                raise ValueError("Invalid token or email.")
            if user.verification_expiry < datetime.now():
                user.verification_token = None
                user.verification_expiry = None
                email = user.profile.email
                session.commit()
                cls.resend_email_verification(email)
                raise ValueError(
                    "Token expired. A new verification link has been sent.")
            user.verified_account = True
            user.verification_token = None
            user.verification_expiry = None
            session.commit()
            return 'email_verified'
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @classmethod
    def send_forgot_password_link(cls, email):
        """
        Function responsible for sending the forgot password link.
        """
        session = get_session()
        try:
            user = session.query(Users.user_id).join(Profiles).filter(
                Profiles.email == email
            ).first()
            if user is None:
                raise EmailNotFoundException("Email not found.")
            reset_token = base64.b64encode(urandom(24)).decode('utf-8')
            reset_expiry = datetime.now() + timedelta(minutes=2880)
            query = (
                update(Users)
                .where(Users.user_id == user[0])
                .values(reset_token=reset_token, reset_expiry=reset_expiry)
            )
            session.execute(query)
            session.commit()
            send_mail(
                email=email,
                message=f"Click the link to reset your password: "
                f"{cls.FRONT_END_FORGOT_PASSWORD_URL}"
                f"{reset_token}",
                subject="Reset Your Password"
            )
            return 'reset_link_sent'
        except (EmailNotFoundException, DataError, OperationalError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @classmethod
    def resend_email_verification(cls, email):
        """
        Function responsible for resending the email verification link.
        """
        session = get_session()
        try:
            query_user_id = (
                select(Users.user_id)
                .where(Users.user_id == Profiles.user_id)
                .where(Profiles.email == email)
            )
            user_id = session.execute(query_user_id)
            if user_id is None:
                raise EmailNotFoundException("Email not found.")
            verification_token = base64.b64encode(
                urandom(24)).decode('utf-8')
            verification_expiry = datetime.now() + timedelta(minutes=2880)
            query = (
                update(Users)
                .where(Users.user_id == user_id)
                .values(verification_token=verification_token,
                        verification_expiry=verification_expiry)
            )
            session.execute(query)
            session.commit()
            send_mail(
                email=email,
                message=f"Click the link to verify your email: "
                f"{Profiles.FRONT_END_VERIFY_EMAIL_URL}"
                f"{verification_token}",
                subject="Verify Your Email"
            )
            return 'verification_link_sent'
        except (EmailNotFoundException, DataError, OperationalError) as e:
            session.rollback()
            raise e
        finally:
            session.close()


Base.metadata.create_all(bind=get_engine())
