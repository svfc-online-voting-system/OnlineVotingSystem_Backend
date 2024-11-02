"""
    The User class contains the following columns:
            - user_id: Integer, primary key, autoincrement
            - uuid: UUID, unique, not null
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
            - deleted_at: Date, nullable
"""
from datetime import datetime

from sqlalchemy import Column, Integer, Date, select, update, Boolean, VARCHAR, BINARY, DateTime
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy.orm import relationship
from sqlalchemy.sql import expression

from app.exception.authorization_exception import (
    EmailNotFoundException,
    PasswordResetExpiredException,
    PasswordResetLinkInvalidException
)
from app.models.base import Base
from app.utils.engine import get_session


class User(Base):  # pylint: disable=R0903
    """Class representing a User in the database."""
    __tablename__ = 'user'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(BINARY(16), nullable=False, unique=True,)
    username = Column(VARCHAR(45), unique=True, nullable=False)
    email = Column(VARCHAR(100), nullable=False)
    firstname = Column(VARCHAR(100), nullable=False)
    lastname = Column(VARCHAR(100), nullable=False)
    date_of_birth = Column(Date, nullable=False)
    creation_date = Column(Date, nullable=False)
    verified_account = Column(
        Boolean, default=expression.false(), nullable=False)
    is_admin = Column(Boolean, default=expression.false(), nullable=False)
    salt = Column(VARCHAR(45), nullable=False)
    hashed_password = Column(VARCHAR(255), nullable=False)
    otp_secret = Column(VARCHAR(20), nullable=True)
    otp_expiry = Column(Date, nullable=True)
    reset_token = Column(VARCHAR(175), nullable=True)
    reset_expiry = Column(Date, nullable=True)
    verification_token = Column(VARCHAR(175), nullable=True)
    verification_expiry = Column(DateTime, nullable=True)
    deleted_at = Column(Date, nullable=True)

    voting_event = relationship(
        'VotingEvent',
        back_populates='user',
        cascade="save-update, merge, expunge, refresh-expire"
    )


class UserOperations:
    """ Class responsible for operation like creating a new user, login, etc. """
    @staticmethod
    def create_new_user(user_data: dict):  # pylint: disable=C0116
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
                salt=user_data.get("salt"),
                hashed_password=user_data.get("hashed_password"),
                verification_token=user_data.get("verification_token"),
                verification_expiry=user_data.get("verification_expiry"),
                verified_account=user_data.get("verified_account"),
            )
            session.add(new_user)
            session.commit()
        except (DataError, IntegrityError, OperationalError, DatabaseError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @staticmethod
    def login(email):  # pylint: disable=C0116
        session = get_session()
        try:
            user = session.execute(
                select(User.hashed_password, User.verified_account)
                .where(User.email == email)
            ).first()
            if user is None:
                raise EmailNotFoundException("Email not found.")
            hashed_password, verified_account = user
            return hashed_password, verified_account

        except (OperationalError, DatabaseError) as e:
            raise e
        finally:
            session.close()

    @staticmethod
    def is_email_verified(email):  # pylint: disable=C0116
        session = get_session()
        try:
            user = session.execute(
                select(User.verified_account)
                .where(User.email == email)).first()
            if user is None:
                raise EmailNotFoundException("Email not found.")
            verified_account = user
            return verified_account
        except OperationalError as e:
            raise e
        finally:
            session.close()

    @staticmethod
    def is_email_exists(email: str) -> bool:  # pylint: disable=C0116
        session = get_session()
        try:
            user = session.execute(select(User.email).filter(
                User.email == email)).first()
            if user is not None:
                return True
            return False
        except (DataError, IntegrityError, OperationalError, DatabaseError) as e:
            raise e
        finally:
            session.close()


class PasswordOperations:
    """ Class responsible for password operations like hashing, verifying, etc. """
    @staticmethod
    def verify_forgot_password_token(reset_token, new_hashed_password, salt):  # pylint: disable=C0116
        session = get_session()
        try:
            user = session.execute(
                select(User.user_id, User.reset_expiry)
                .where(User.reset_token == reset_token)).scalars().first()
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
                raise PasswordResetExpiredException(
                    "Password reset link has expired.")
            return PasswordOperations.password_reset(new_hashed_password, salt, user[0])
        except (PasswordResetExpiredException, PasswordResetLinkInvalidException,
                DataError, OperationalError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @staticmethod
    def password_reset(new_hashed_password, salt, user_id):  # pylint: disable=C0116
        session = get_session()
        try:
            query = (
                update(User)
                .where(User.user_id == user_id)
                .values(salt=salt, hashed_password=new_hashed_password)
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
    def set_otp(email, otp, expiry):  # pylint: disable=C0116
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
    def get_otp(email):  # pylint: disable=C0116
        session = get_session()
        try:
            result = session.execute(
                select(User.otp_secret, User.otp_expiry, User.user_id)
                .where(User.email == email)).first()
            return result.otp_secret, result.otp_expiry, result.user_id # type: ignore
        except (OperationalError, DatabaseError) as e:
            raise e
        finally:
            session.close()

    @staticmethod
    def invalidate_otp(email: str):
        """ Function to invalidate the OTP that is currently set in the database
        in case of an expired otp is being the input
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
    """ Class responsible for email verification operations like verifying, resending, etc. """
    @staticmethod
    def verify_email(token):  # pylint: disable=C0116
        session = get_session()
        try:
            result = session.execute(
                select(
                    User.verification_expiry,
                    User.verification_token,
                    User.email
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
                .values(verified_account=True, verification_token=None, verification_expiry=None)
            )
            session.commit()
            return 'email_verified'

        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @staticmethod
    def resend_email_verification(email, verification_expiry, verification_token):  # pylint: disable=C0116
        session = get_session()
        try:
            session.execute(
                update(User)
                .where(User.email == email)
                .values(verification_token=verification_token,
                        verification_expiry=verification_expiry)
            )
            session.commit()
        except (EmailNotFoundException, DataError, OperationalError) as e:
            session.rollback()
            raise e
        finally:
            session.close()


class ForgotPasswordOperations:  # pylint: disable=R0903
    """ Class responsible for forgot password operations like sending reset link, verifying, etc. """
    @staticmethod
    def send_forgot_password_link(email, reset_token, reset_expiry):  # pylint: disable=C0116
        session = get_session()
        try:
            result = session.execute(
                select(User.user_id, User.firstname)
                .where(User.email == email)
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
