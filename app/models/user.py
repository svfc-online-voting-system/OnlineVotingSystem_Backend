"""
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
            - is_admin: Boolean, not null, default False
            - verified_account: Boolean, not null, default False
            - verification_token: String, nullable
            - verification_expiry: Date, nullable
            - otp_secret: String, nullable
            - otp_expiry: Date, nullable
            - reset_token: String, nullable
            - reset_expiry: Date, nullable
"""
import base64
import uuid
import hashlib
from datetime import datetime, timedelta
from os import getenv, urandom
import time
import bcrypt
import pyotp
from sqlalchemy import Column, Integer, Date, select, update, Boolean, VARCHAR, BINARY
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy.sql import expression
from app.utils.engine import get_session
from app.exception.authorization_exception import (EmailNotFoundException, OTPExpiredException,
                                                   OTPIncorrectException,
                                                   PasswordResetExpiredException,
                                                   PasswordResetLinkInvalidException)
from app.models.base import Base

class User(Base):  # pylint: disable=R0903
    """Class representing a User in the database."""
    __tablename__ = 'user'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(BINARY(length=16), nullable=False, unique=True)
    username = Column(VARCHAR(length=45), unique=True, nullable=False)
    email = Column(VARCHAR(length=100), nullable=False)
    firstname = Column(VARCHAR(length=100), nullable=False)
    lastname = Column(VARCHAR(length=100), nullable=False)
    date_of_birth = Column(Date, nullable=False)
    creation_date = Column(Date, nullable=False)
    verified_account = Column(Boolean, default=expression.false(), nullable=False)
    is_admin = Column(Boolean, default=expression.false(), nullable=False)
    salt = Column(VARCHAR(45), nullable=False)
    hashed_password = Column(VARCHAR(255), nullable=False)
    otp_secret = Column(VARCHAR(20), nullable=True)
    otp_expiry = Column(Date, nullable=True)
    reset_token = Column(VARCHAR(175), nullable=True)
    reset_expiry = Column(Date, nullable=True)
    verification_token = Column(VARCHAR(175), nullable=True)
    verification_expiry = Column(Date, nullable=True)
    deleted_at = Column(Date, nullable=True)
    # votes = relationship('Votes',
    #                      back_populates='users',
    #                      uselist=False, cascade="all, delete-orphan")
    # ballots = relationship("Ballots",
    #                         back_populates="users", cascade="all, delete-orphan")
    # poll_votes = relationship("PollVotes",
    #                             back_populates="users", cascade="all, delete-orphan")

class UserOperations:
    """ Class responsible for operation like creating a new user, login, etc. """
    @staticmethod
    def create_new_user(user_data: dict):  # pylint: disable=C0116
        session = get_session()
        try:
            new_user = User(
                uuid=uuid.uuid4().bytes,
                username=user_data.get("username"),
                email=user_data.get("email"),
                firstname=user_data.get("first_name").capitalize(),
                lastname=user_data.get("last_name").capitalize(),
                date_of_birth=user_data.get("date_of_birth"),
                creation_date=user_data.get("creation_date"),
                is_admin=user_data.get("is_admin"),
                salt=user_data.get("salt"),
                hashed_password=user_data.get("password"),
                verification_token=user_data.get("email_verification_token"),
                verification_expiry=user_data.get("email_verification_expiry"),
                verified_account=user_data.get("verified_account"),
            )
            session.add(new_user)
            session.commit()
            return new_user.user_id
        except (DataError, IntegrityError, OperationalError, DatabaseError) as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    @staticmethod
    def login(email):  # pylint: disable=C0116
        session = get_session()
        try:
            user_with_profile_stmt = (
                select(User.email, User.hashed_password, User.salt)
                .where(User.email == email)
            )
            user_with_profile = session.execute(user_with_profile_stmt).first()
            if user_with_profile is None:
                raise EmailNotFoundException("Email not found.")
            email, hashed_password, salt = user_with_profile
            return {
                'email': email,
                'password': hashed_password,
                'salt': salt
            }
        except (OperationalError, DatabaseError) as e:
            session.rollback()
            raise e
        except EmailNotFoundException as e:
            session.rollback()
            raise e
        finally:
            session.close()
        
    @staticmethod
    def is_email_verified(email):  # pylint: disable=C0116
        session = get_session()
        try:
            user = session.query(User.verified_account).filter(User.email == email).first()
            return bool(user.verified_account)
        except OperationalError as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    @staticmethod
    def is_email_exists(email):  # pylint: disable=C0116
        session = get_session()
        try:
            user = session.query(User.email).filter(User.email == email).first()
            return bool(user)
        except (DataError, IntegrityError, OperationalError, DatabaseError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

class PasswordOperations:
    """ Class responsible for password operations like hashing, verifying, etc. """
    @staticmethod
    def verify_forgot_password_token(reset_token, new_password):  # pylint: disable=C0116
        session = get_session()
        try:
            user = session.execute(select(User.user_id, User.reset_expiry)
                                   .where(User.reset_token == reset_token)).first()
            if user is None:
                raise PasswordResetLinkInvalidException("Invalid reset token.")
            if user[1] < datetime.now():
                query = (
                    update(User)
                    # .where(Users.user_id == user[0])
                    # .where(Profiles.user_id == user[0])
                    .where(User.user_id == user[0])
                    .values(reset_token=None, reset_expiry=None)
                )
                session.execute(query)
                session.commit()
                raise PasswordResetExpiredException(
                    "Password reset link has expired.")
            return PasswordOperations.password_reset(new_password, user[0])
        except (PasswordResetExpiredException, PasswordResetLinkInvalidException,
                DataError, OperationalError) as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    @staticmethod
    def password_reset(new_password, user_id):  # pylint: disable=C0116
        session = get_session()
        try:
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
        except (OperationalError, DatabaseError, DatabaseError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

class OtpOperations:
    """ Class responsible for OTP operations like generating, verifying, etc. """
    @staticmethod
    def generate_otp(email):  # pylint: disable=C0116
        session = get_session()
        try:
            seed = f"{getenv('TOTP_SECRET_KEY')}{int(time.time())}"
            seven_digit_otp = pyotp.TOTP(base64.b32encode(bytes.fromhex(seed))
                                         .decode('UTF-8'),
                                         digits=7, interval=300, digest=hashlib.sha256).now()
            otp_expiry: datetime = datetime.now() + timedelta(minutes=5)
            query = (
                update(User)
                .where(User.email == email)
                .values(otp_secret=seven_digit_otp, otp_expiry=otp_expiry)
            )
            get_name = select(User.firstname).where(User.email == email)
            session.execute(query)
            session.commit()
            return seven_digit_otp, session.execute(get_name).first()[0]
        except (OperationalError, DatabaseError, DataError) as e:
            session.rollback()
            raise e
        finally:
            session.close()
            
    @staticmethod
    def verify_otp(email, otp):  # pylint: disable=C0116
        session = get_session()
        try:
            user_otp_secret, user_otp_expiry = session.execute(select(User.otp_secret, User.otp_expiry)
                                                               .where(User.email == email)).first()
            if user_otp_secret is None or user_otp_expiry is None:
                raise OTPExpiredException("OTP has expired.")
            if user_otp_expiry < datetime.now():
                query = (
                    update(User)
                    .where(User.email == email)
                    .values(otp_secret=None, otp_expiry=None)
                )
                session.execute(query)
                session.commit()
                raise OTPExpiredException("OTP has expired.")
            if int(user_otp_secret) != int(otp):
                raise OTPIncorrectException("Incorrect OTP.")
            query = (
                update(User)
                .where(User.email == email)
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

class EmailVerificationOperations:
    """ Class responsible for email verification operations like verifying, resending, etc. """
    @staticmethod
    def verify_email(token):  # pylint: disable=C0116
        session = get_session()
        try:
            user = session.execute(
                select(User).where(User.verification_token == token)
            ).scalars().first()
            if user is None:
                raise ValueError("Invalid token.")
            if user.verification_expiry < datetime.now():
                user.verification_token = None
                user.verification_expiry = None
                email = user.profile.email
                session.commit()
                return email
            user.verified_account = True
            user.verification_token = None
            user.verification_expiry = None
            session.commit()
            print("Email verified.")
            return 'email_verified'
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    @staticmethod
    def resend_email_verification(email):  # pylint: disable=C0116
        session = get_session()
        try:
            query_user_id_and_name = (
                select(User.user_id, User.firstname)
                .where(User.email == email)
            )
            user_id, first_name = session.execute(query_user_id_and_name)
            if user_id is None:
                raise EmailNotFoundException("Email not found.")
            verification_token = base64.b64encode(
                urandom(24)).decode('utf-8')
            verification_expiry = datetime.now() + timedelta(minutes=2880)
            query = (
                update(User)
                .where(User.user_id == user_id)
                .values(verification_token=verification_token,
                        verification_expiry=verification_expiry)
            )
            session.execute(query)
            session.commit()
            return verification_token, first_name
        except (EmailNotFoundException, DataError, OperationalError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

class ForgotPasswordOperations:  # pylint: disable=R0903
    """ Class responsible for forgot password operations like sending reset link, verifying, etc. """
    @staticmethod
    def send_forgot_password_link(email):  # pylint: disable=C0116
        session = get_session()
        try:
            user_id, first_name = session.execute(
                select(User.user_id, User.firstname)
                .where(User.email == email)
            ).first()
            if user_id is None:
                raise EmailNotFoundException("Email not found.")
            reset_token = base64.b64encode(urandom(128)).decode('utf-8')
            reset_expiry = datetime.now() + timedelta(minutes=60)
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
