"""
    This is the service layer for the authentication.
    It is responsible for the login and registration of the user.
    Furthermore, it is also responsible for generating the session token.
    Additionally, it is also responsible for handling the exceptions
"""
import time
import base64
import hashlib
from os import urandom, getenv
from datetime import datetime, timedelta
from base64 import urlsafe_b64encode
from logging import getLogger

import pyotp
from jwt import ExpiredSignatureError, InvalidTokenError
import flask_wtf.csrf
from flask import render_template
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from bcrypt import hashpw, gensalt, checkpw
from sqlalchemy.exc import DataError, IntegrityError, DatabaseError, OperationalError

from app.extension import csrf
from app.exception.authorization_exception import (
    EmailAlreadyTaken, EmailNotFoundException,
    OTPExpiredException, OTPIncorrectException,
    AccountNotVerifiedException, PasswordIncorrectException)
from app.models.user import (
    UserOperations, OtpOperations, PasswordOperations,
    ForgotPasswordOperations, EmailVerificationOperations)
from app.utils.email_utility import send_mail


logger = getLogger(__name__)


class AuthService:
    """ This class is responsible for the authentication of the user. """
    @classmethod
    def register(cls, user_data):  # pylint: disable=C0116
        return UserRegistrationService.register_user(user_data)

    @classmethod
    def login(cls, email, plaintext_password):  # pylint: disable=C0116
        return UserLoginService.login_user(email, plaintext_password)

    @staticmethod
    def verify_token():  # pylint: disable=C0116
        return TokenVerificationService.verify_token()

    @staticmethod
    def generate_otp(email):  # pylint: disable=C0116
        return OTPService.generate_otp(email)

    @staticmethod
    def verify_otp(email, otp):  # pylint: disable=C0116
        return OTPService.verify_otp(email, otp)

    @staticmethod
    def send_forgot_password_link(email):  # pylint: disable=C0116
        return ForgotPasswordService.send_forgot_password_link(email)

    @staticmethod
    def verify_forgot_password_token(token, new_password):  # pylint: disable=C0116
        return ForgotPasswordService.verify_forgot_password_token(token, new_password)

    @staticmethod
    def verify_email(token):  # pylint: disable=C0116
        return EmailVerificationService.verify_email(token)

    @staticmethod
    def resend_email_verification(email):  # pylint: disable=C0116
        return EmailVerificationService.resend_email_verification(email)


class UserRegistrationService:  # pylint: disable=R0903
    """ This class is responsible for the user registration service. """
    @staticmethod
    def register_user(user_data):  # pylint: disable=C0116
        try:
            front_end_verify_email_url = getenv(
                'LOCAL_FRONTEND_URL', '') + 'auth/verify-email/'
            is_email_exists = UserOperations.is_email_exists(
                user_data.get('email'))
            if is_email_exists:
                raise EmailAlreadyTaken('Email already taken.')
            salt = gensalt(rounds=16).decode('utf=8')
            hashed_password = hashpw(user_data.get('password').encode(
                'utf-8'), salt.encode('utf-8')).decode('utf-8')
            email_verification_token = (urlsafe_b64encode(urandom(128))
                                        .decode('utf-8').rstrip('='))
            email = user_data.get('email')
            first_name = str(user_data.get('first_name')).capitalize()
            last_name = str(user_data.get('last_name')).capitalize()
            date_of_birth = user_data.get('date_of_birth')

            new_user_data = {
                'salt': salt,
                'password': hashed_password,
                'email_verification_token': email_verification_token,
                'email_verification_expiry': datetime.now() + timedelta(days=2),
                'verified_account': False,
                'username': email.split('@')[0],
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'date_of_birth': date_of_birth,
                'creation_date': datetime.now(),
                'is_admin': user_data.get('is_admin')
            }

            user_id = UserOperations.create_new_user(new_user_data)
            message = render_template(
                "auth/welcome.html",
                verification_url=f"{front_end_verify_email_url}{
                    email_verification_token}",
                user_name=user_data.get('first_name').capitalize())
            send_mail(message=message,
                      email=user_data.get('email'),
                      subject="VoteVoyage Onboarding 🎉")
            return user_id
        except EmailAlreadyTaken as e:
            raise e
        except (IntegrityError, DataError, DatabaseError, OperationalError) as ex:
            raise ex


class UserLoginService:  # pylint: disable=R0903
    """ This class is responsible for the user login service. """
    @staticmethod
    def login_user(email, plaintext_password):  # pylint: disable=C0116
        try:
            user_data = UserOperations.login(email)
            user_email = user_data.get('email')
            user_password = str(user_data.get('password'))
            user_salt = user_data.get('salt')
            is_verified = UserOperations.is_email_verified(email)
            if not is_verified:
                raise AccountNotVerifiedException('Account not verified.')
            if user_email is None and user_password is None and user_salt is None:
                raise EmailNotFoundException('Email not found.')
            is_password_matched = checkpw(
                plaintext_password.encode('utf-8'),
                user_password.encode('utf-8'))
            if not is_password_matched:
                raise PasswordIncorrectException('Password incorrect.')
            result = OTPService.generate_otp(email)
            if result == 'success':
                return 'success'
            return None
        except (OperationalError, ValueError,
                PasswordIncorrectException,
                EmailNotFoundException,
                AccountNotVerifiedException) as e:
            raise e


class PasswordService:  # pylint: disable=R0903
    """ This class is responsible for the password service. """
    @staticmethod
    def hash_password(password):
        """This is the function responsible for hashing the password."""
        return hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

    @staticmethod
    def check_password(plaintext_password, hashed_password):
        """This is the function responsible for checking the password."""
        return checkpw(plaintext_password.encode('utf-8'), hashed_password.encode('utf-8'))


class OTPService:  # pylint: disable=R0903
    """ This class is responsible for the OTP service. """
    @staticmethod
    def generate_otp(email):  # pylint: disable=C0116
        try:
            seed = f"{getenv('TOTP_SECRET_KEY')}{int(time.time())}"
            seven_digit_otp = pyotp.TOTP(
                base64.b32encode(bytes.fromhex(seed))
                .decode('UTF-8'), digits=7, interval=300, digest=hashlib.sha256).now()
            otp_expiry: datetime = datetime.now() + timedelta(minutes=5)
            seven_digit_otp, first_name = OtpOperations.set_otp(
                email=email, otp=seven_digit_otp, expiry=otp_expiry)
            otp_template = render_template(
                "auth/one-time-password.html",
                otp=seven_digit_otp, user_name=first_name)
            subject = "Your OTP Verification code"
            send_mail(message=otp_template, email=email, subject=subject)
            return 'success'
        except (OperationalError, ValueError, EmailNotFoundException) as e:
            raise e

    @staticmethod
    def verify_otp(email, otp):  # pylint: disable=C0116
        try:
            if not email or not otp:
                raise ValueError("Email and OTP are required.")
            is_user_exists = UserOperations.is_email_exists(email)
            if not is_user_exists:
                raise EmailNotFoundException('Email not found.')
            user_id = OtpOperations.verify_otp(email=email, otp=otp)
            if user_id:
                return (SessionTokenService
                        .generate_session_token(email, user_id),
                        CSRFTokenService.generate_csrf_token())
            return None
        except (OperationalError, ValueError, OTPExpiredException, OTPIncorrectException,
                EmailNotFoundException) as e:
            raise e


class SendMailService:  # pylint: disable=R0903
    """ This class is responsible for the send mail service. """
    @staticmethod
    def send_mail(message, email, subject):  # pylint: disable=C0116
        return send_mail(message=message, email=email, subject=subject)


class TokenVerificationService:  # pylint: disable=R0903
    """ This class is responsible for the token verification service. """
    @staticmethod
    @jwt_required(locations=['cookies', 'headers'])
    def verify_token():  # pylint: disable=C0116
        try:
            jwt_identity = csrf.validate()
            logger.info("JWT Identity verified for user: %s", jwt_identity)
            return {'code': 'success', 'message': 'JWT Identity verified.'}, 200
        except (ExpiredSignatureError, InvalidTokenError) as e:
            raise e


class CSRFTokenService:  # pylint: disable=R0903
    """ This class is responsible for the CSRF token service. """
    @staticmethod
    def generate_csrf_token():
        """This is the function responsible for generating the CSRF token."""
        return flask_wtf.csrf.generate_csrf()


class SessionTokenService:  # pylint: disable=R0903
    """ This class is responsible for the session token service. """
    @staticmethod
    def generate_session_token(email, user_id):
        """This is the function responsible for generating the session token."""
        return create_access_token(identity={'email': email, 'user_id': user_id})


class ForgotPasswordService:
    """ This class is responsible for the forgot password service. """
    @staticmethod
    def send_forgot_password_link(email):
        front_end_forgot_password_url = getenv(
            'LOCAL_FRONTEND_URL') + '/reset-password/'
        """This is the function responsible for sending the forgot password link."""
        reset_token, first_name = ForgotPasswordOperations.send_forgot_password_link(
            email)
        reset_password_url = front_end_forgot_password_url + reset_token
        forgot_password_template = render_template("auth/forgot-password.html",
                                                   reset_password_url=reset_password_url, user_name=first_name)
        SendMailService.send_mail(
            email=email, subject="Reset Password", message=forgot_password_template)
        return 'success'

    @staticmethod
    def verify_forgot_password_token(token, new_password):
        """This is the function responsible for verifying the forgot password token."""
        return PasswordOperations.verify_forgot_password_token(token, new_password)


class EmailVerificationService:
    """ This class is responsible for the email verification service. """
    @staticmethod
    def verify_email(token):
        """This is the function responsible for verifying the email."""
        result = EmailVerificationOperations.verify_email(token)
        if result != 'email_verified':
            EmailVerificationService.resend_email_verification(email=result)
        return result

    @staticmethod
    def resend_email_verification(email):
        """This is the function responsible for resending the email verification."""
        verification_token, first_name = EmailVerificationOperations.resend_email_verification(
            email)
        verification_url = getenv('LOCAL_FRONTEND_URL') + \
            getenv('API_VERIFY_EMAIL') + verification_token
        verification_template = render_template("auth/welcome.html",
                                                verification_url=verification_url, user_name=first_name)
        SendMailService.send_mail(
            email=email, subject="Verify your email", message=verification_template)
