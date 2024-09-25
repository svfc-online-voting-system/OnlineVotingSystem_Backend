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

from sqlalchemy import Column, Integer, String, Date, select, update
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import IntegrityError, DataError, OperationalError
import bcrypt
import pyotp

from app.utils.email_utility import send_mail
from app.utils.engine import get_session, get_engine
from app.exception.password_error import PasswordErrorException
from app.exception.email_not_found_error import EmailNotFoundException
from app.exception.otp_expired import OTPExpiredException
from app.exception.otp_incorrect import OTPIncorrectException
from app.exception.password_reset_expired import PasswordResetExpiredException
from app.exception.password_reset_link_invalid import PasswordResetLinkInvalidException

Base = declarative_base()


class User(Base):
    """Class representing a User in the database."""
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(45), unique=True, nullable=False)
    salt = Column(String(45), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    date_of_birth = Column(Date, nullable=False)
    account_creation_date = Column(Date, nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    otp_secret = Column(String(20), nullable=True)
    otp_expiry = Column(Date, nullable=True)
    reset_token = Column(String(175), nullable=True)
    reset_expiry = Column(Date, nullable=True)
    FRONT_END_FORGOT_PASSWORD_URL = os.getenv('LOCAL_FRONTEND_URL') + '/reset-password/'

    @classmethod
    def create_user(cls, user_data_dict):
        """ Creates a new user in the database. """
        account_creation_date = datetime.now()
        session = get_session()
        first_name, last_name, email, plaintext_password, date_of_birth = (
            user_data_dict.get('first_name'),
            user_data_dict.get('last_name'),
            user_data_dict.get('email'),
            user_data_dict.get('password'),
            user_data_dict.get('date_of_birth')
        )

        try:
            salt = bcrypt.gensalt(rounds=16).decode('utf=8')
            hashed_password = bcrypt.hashpw(plaintext_password.encode(
                'utf-8'), salt.encode('utf-8')).decode('utf-8')

            new_user = cls(
                username=email.split("@")[0],
                salt=salt,
                hashed_password=hashed_password,
                email=email,
                date_of_birth=date_of_birth,
                account_creation_date=account_creation_date,
                first_name=first_name.capitalize(),
                last_name=last_name.capitalize()
            )

            session.add(new_user)
            session.commit()
            return new_user
        except IntegrityError as int_err:
            session.rollback()
            raise int_err
        except DataError as data_err:
            session.rollback()
            raise data_err
        except Exception as e:
            session.rollback()
            raise e

    @classmethod
    def get_user_by_email(cls, email):
        """Retrieves a user from the database by email."""
        session = get_session()
        return session.query(cls).filter_by(email=email).first()

    @classmethod
    def check_credentials(cls, email, plaintext_password):
        """Checks the credentials of a user."""
        session = get_session()

        hashed_password_row = session.execute(
            select(User.hashed_password).filter_by(email=email)).first()

        if hashed_password_row is None:
            raise EmailNotFoundException

        hashed_password_from_db = hashed_password_row[0]

        if bcrypt.checkpw(
            plaintext_password.encode('utf-8'),
            hashed_password_from_db.encode('utf-8')
        ):
            return session.execute(select(User.user_id)
                                   .filter_by(email=email)).first()
        raise PasswordErrorException
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
                raise ValueError
            user = cls.get_user_by_email(email)
            if user is None:
                raise EmailNotFoundException
            reset_token = base64.b64encode(os.urandom(128)).decode('utf-8')
            reset_expiry = datetime.now() + timedelta(minutes=30)
            subject = "Password Reset Link"
            message = (f"Click the link to reset your password: "
                       f"{cls.FRONT_END_FORGOT_PASSWORD_URL}{reset_token}"
                       f"\n\nThis link will expire in 30 minutes.")
            session.execute(update(User).where(User.email == email)
                            .values(reset_token=reset_token, reset_expiry=reset_expiry))
            if send_mail(email=user.email, message=message, subject=subject):
                session.commit()
                return 'reset_link_sent'
            raise OperationalError
        except OperationalError as oe:
            session.rollback()
            raise oe
        except ValueError as ve:
            session.rollback()
            raise ve
        except EmailNotFoundException as enf:
            session.rollback()
            raise enf
    @classmethod
    def verify_forgot_password_token(cls, reset_token, new_password) -> str:
        """
        Function responsible for verifying the reset token.
        """
        session = get_session()
        try:
            if not reset_token or not new_password:
                raise ValueError
            user = session.execute(select(User.user_id, User.reset_expiry)
                                   .where(User.reset_token == reset_token)).first()
            if user is None:
                raise PasswordResetLinkInvalidException
            if user[1] < datetime.now():
                session.execute(update(User).where(User.reset_token == reset_token)
                                .values(reset_token=None, reset_expiry=None))
                session.commit()
                raise PasswordResetExpiredException
            return cls.password_reset(new_password, user[0])
        except PasswordResetExpiredException as pree:
            session.rollback()
            raise pree
        except PasswordResetLinkInvalidException as prli:
            session.rollback()
            raise prli
        except ValueError as ve:
            session.rollback()
            raise ve
        except DataError as de:
            session.rollback()
            print(de)
            raise de
        except OperationalError as oe:
            session.rollback()
            print(oe)
            raise oe

    @classmethod
    def password_reset(cls, new_password, user_id):
        """
        Function responsible for resetting the password.
        """
        session = get_session()
        try:
            if not new_password or not user_id:
                raise ValueError
            salt = bcrypt.gensalt(rounds=16).decode('utf=8')
            hashed_password = (bcrypt.hashpw(new_password.encode('utf-8'), salt.encode('utf-8'))
                               .decode('utf-8'))
            session.execute(update(User).where(User.user_id == user_id)
                            .values(salt=salt, hashed_password=hashed_password))
            session.commit()
            return 'password_reset'
        except ValueError as ve:
            session.rollback()
            raise ve
        except Exception as e:
            session.rollback()
            raise e
    @classmethod
    def generate_otp(cls, email) -> str:
        """
        Function responsible for generating OTP Code
        that also verifies if the email does exist.
        """
        session = get_session()
        try:
            if not email:
                raise ValueError
            user = cls.get_user_by_email(email)
            if user is None:
                raise EmailNotFoundException
            unique_seed = f"{os.getenv('TOTP_SECRET_KEY')}{int(time.time())}"
            seven_digit_otp = pyotp.TOTP(base64.b32encode(bytes.fromhex(unique_seed))
                                         .decode('UTF-8'),
                                         digits=7, interval=300, digest=hashlib.sha256).now()
            otp_expiry = datetime.now() + timedelta(minutes=5)
            subject = "Your OTP Verification code"
            message =\
                f"Here's your OTP Code: {seven_digit_otp}. Use this to get access to your account."
            session.execute(update(User).where(User.email == email)
                            .values(otp_secret=seven_digit_otp, otp_expiry=otp_expiry))
            if send_mail(email=user.email, message=message, subject=subject):
                session.commit()
                return 'otp_sent'
            raise OperationalError
        except OperationalError as oe:
            session.rollback()
            raise oe
        except ValueError as ve:
            session.rollback()
            raise ve
        except EmailNotFoundException as enf:
            session.rollback()
            raise enf
        except Exception as e:
            session.rollback()
            raise e
    @classmethod
    def verify_otp(cls, email, otp) -> str:
        """Function responsible for verifying the OTP Code."""
        session = get_session()
        try:
            if not email or not otp:
                raise ValueError
            user = cls.get_user_by_email(email)
            if user is None:
                raise EmailNotFoundException
            user_otp = session.execute(select(User.otp_secret, User.otp_expiry)
                                       .where(User.email == email)).first()
            if user_otp[0] is None or user_otp[1] is None:
                raise OTPExpiredException
            if user_otp[1] < datetime.now():
                session.execute(update(User).where(User.email == email)
                                .values(otp_secret=None, otp_expiry=None))
                session.commit()
                raise OTPExpiredException
            if int(user_otp[0]) != int(otp):
                raise OTPIncorrectException
            session.execute(update(User).where(User.email == email)
                            .values(otp_secret=None, otp_expiry=None))
            session.commit()
            return 'otp_verified'
        except OperationalError as oe:
            session.rollback()
            raise oe
        except OTPExpiredException as oee:
            session.rollback()
            raise oee
        except ValueError as ve:
            session.rollback()
            raise ve
        except OTPIncorrectException as oie:
            session.rollback()
            raise oie
        except EmailNotFoundException as enf:
            session.rollback()
            raise enf
        except Exception as e:
            session.rollback()
            raise e


Base.metadata.create_all(bind=get_engine())
