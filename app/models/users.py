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
from datetime import datetime, timedelta
import os
import time

from sqlalchemy import Column, Integer, String, Date, select, update, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
import bcrypt
import pyotp
from sqlalchemy.sql import expression

from app.models.user_profile import UserProfile
from app.utils.email_utility import send_mail
from app.utils.engine import get_session, get_engine
from app.exception.authorization_exception import (EmailNotFoundException, OTPExpiredException,
                                                   OTPIncorrectException, PasswordResetExpiredException,
                                                   PasswordResetLinkInvalidException, PasswordErrorException)
from app.models.base import Base


class User(Base):
    """Class representing a User in the database."""
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    salt = Column(String(45), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    otp_secret = Column(String(20), nullable=True)
    otp_expiry = Column(Date, nullable=True)
    reset_token = Column(String(175), nullable=True)
    reset_expiry = Column(Date, nullable=True)
    verified_account = Column(Boolean, default=expression.false(), nullable=False)
    verification_token = Column(String(175), nullable=True)
    verification_expiry = Column(Date, nullable=True)
    
    profile = relationship("UserProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    
    FRONT_END_FORGOT_PASSWORD_URL = os.getenv('LOCAL_FRONTEND_URL') + '/reset-password/'

    @classmethod
    def create_new_user(cls, user_data: dict):
        """Create a new user in the database."""
        session = get_session()
        try:
            new_user = cls(
                salt=user_data.get("salt"),
                hashed_password=user_data.get("password"),
                verification_token=user_data.get("email_verification_token"),
                verification_expiry=datetime.now() + timedelta(minutes=1440),
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
    def get_user_by_email(cls, email):
        """Retrieves a user from the database by email."""
        session = get_session()
        try:
            stmt = (
                select(User.user_id, UserProfile.email)
                .where(User.user_id == UserProfile.user_id)
                .where(UserProfile.email == email)
            )
            result = session.execute(stmt).first()
            return result
        except OperationalError as oe:
            session.rollback()
            raise oe
        finally:
            session.close()
    
    @classmethod
    def check_credentials(cls, email, plaintext_password):
        """Checks the credentials of a user."""
        session = get_session()
        try:
            hashed_password_row = session.query(select(User.hashed_password).join(UserProfile)
                                                .where(UserProfile.email == email)).first()
            if hashed_password_row is None:
                raise EmailNotFoundException("Email not found.")
            hashed_password_from_db = hashed_password_row[0]
            if bcrypt.checkpw(
                plaintext_password.encode('utf-8'),
                hashed_password_from_db.encode('utf-8')
            ):
                return session.query(select(User.user_id).join(UserProfile)
                                     .where(UserProfile.email == email)).first()[0]
            raise PasswordErrorException("Invalid Password")
        except (OperationalError, ValueError) as e:
            session.rollback()
            raise e
        except (EmailNotFoundException, PasswordErrorException) as err:
            session.rollback()
            raise err
        finally:
            session.close()
    
    @classmethod
    def send_forgot_password_link(cls, email) -> str:
        """
        Forgot password functionality function.
        In compliance with OWASP Recommendations. the password reset token should
        be generated cryptographically secure and should be stored in the database.
        Additionally, it should be invalidated once the reset link is used and a successful
        reset of password happens or after a certain time frame.
        """
        session = get_session()
        try:
            if not email:
                raise ValueError("Email is required.")
            user = cls.get_user_by_email(email)
            if user is None:
                raise EmailNotFoundException("Email not found.")
            reset_token = base64.b64encode(os.urandom(128)).decode('utf-8')
            token_expiry_minutes = int(os.getenv('TOKEN_EXPIRY_MINUTES', '30'))
            reset_expiry = datetime.now() + timedelta(minutes=30)
            subject = "Password Reset Link"
            message = (f"Click the link to reset your password: "
                       f"{cls.FRONT_END_FORGOT_PASSWORD_URL}{reset_token}"
                       f"\n\nThis link will expire in {token_expiry_minutes} minutes.")
            update_stmt = (
                update(User)
                .where(User.user_id == UserProfile.user_id)
                .where(UserProfile.email == email)
                .values(reset_token=reset_token, reset_expiry=reset_expiry)
            )
            session.execute(update_stmt)
            send_mail(email=user.email, message=message, subject=subject)
            session.commit()
            return 'reset_link_sent'
        except (EmailNotFoundException, ValueError, OperationalError) as e:
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
            if not reset_token or not new_password:
                raise ValueError("Reset token and new password are required.")
            user = session.execute(select(User.user_id, User.reset_expiry)
                                   .where(User.reset_token == reset_token)).first()
            if user is None:
                raise PasswordResetLinkInvalidException("Invalid reset token.")
            if user[1] < datetime.now():
                query = (
                    update(User)
                    .where(User.user_id == user[0])
                    .where(UserProfile.user_id == user[0])
                    .values(reset_token=None, reset_expiry=None)
                )
                session.execute(query)
                session.commit()
                raise PasswordResetExpiredException("Password reset link has expired.")
            return cls.password_reset(new_password, user[0])
        except (PasswordResetExpiredException, PasswordResetLinkInvalidException,
                ValueError, DataError, OperationalError) as e:
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
            if not new_password or not user_id:
                raise ValueError("New password and user_id are required.")
            salt = bcrypt.gensalt(rounds=16).decode('utf=8')
            hashed_password = (bcrypt.hashpw(new_password.encode('utf-8'), salt.encode('utf-8'))
                               .decode('utf-8'))
            query = (
                update(User)
                .where(User.user_id == user_id)
                .values(salt=salt, hashed_password=hashed_password)
            )
            session.execute(query)
            session.commit()
            return 'password_reset'
        except (OperationalError, ValueError) as e:
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
            if not email:
                raise ValueError("Email is required.")
            user = cls.get_user_by_email(email)
            if user is None:
                raise EmailNotFoundException("Email not found.")
            seed = f"{os.getenv('TOTP_SECRET_KEY')}{int(time.time())}"
            seven_digit_otp = pyotp.TOTP(base64.b32encode(bytes.fromhex(seed))
                                         .decode('UTF-8'),
                                         digits=7, interval=300, digest=hashlib.sha256).now()
            otp_expiry = datetime.now() + timedelta(minutes=5)
            subject = "Your OTP Verification code"
            message = \
                f"Here's your OTP Code: {seven_digit_otp}. Use this to get access to your account."
            query = (
                update(User)
                .where(User.user_id == UserProfile.user_id)
                .where(UserProfile.email == email)
                .values(otp_secret=seven_digit_otp, otp_expiry=otp_expiry)
            )
            session.execute(query)
            send_mail(email=user.email, message=message, subject=subject)
            session.commit()
            return 'otp_sent'
        except (OperationalError, ValueError, EmailNotFoundException) as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    @classmethod
    def verify_otp(cls, email, otp) -> str:
        """Function responsible for verifying the OTP Code."""
        session = get_session()
        try:
            if not email or not otp:
                raise ValueError("Email and OTP are required.")
            user = cls.get_user_by_email(email)
            if user is None:
                raise EmailNotFoundException("Email not found.")
            user_otp_query = session.execute(
                select(User.otp_secret, User.otp_expiry)
                .where(User.user_id == UserProfile.user_id)
                .where(UserProfile.email == email)
            ).first()
            user_otp_secret, user_otp_expiry = user_otp_query
            session.execute(user_otp_query).first()
            if user_otp_secret is None or user_otp_expiry is None:
                raise OTPExpiredException("OTP has expired.")
            if user_otp_expiry < datetime.now():
                query = (
                    update(User)
                    .where(User.user_id == UserProfile.user_id)
                    .where(UserProfile.email == email)
                    .values(otp_secret=None, otp_expiry=None)
                )
                session.execute(query)
                session.commit()
                raise OTPExpiredException("OTP has expired.")
            if int(user_otp_query[0]) != int(otp):
                raise OTPIncorrectException("Incorrect OTP.")
            query = (
                update(User)
                .where(User.user_id == UserProfile.user_id)
                .where(UserProfile.email == email)
                .values(otp_secret=None, otp_expiry=None)
            )
            session.execute(query)
            session.commit()
            return 'otp_verified'
        except (OperationalError, ValueError, OTPExpiredException, OTPIncorrectException,
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
            result = session.query(select(User.verified_account)
                                   .where(User.user_id == UserProfile.user_id)
                                   .where(UserProfile.email == email)).first()
            is_verified = result
            if is_verified:
                return True
            return False
        except OperationalError as e:
            session.rollback()
            raise e
        finally:
            session.close()


Base.metadata.create_all(bind=get_engine())
