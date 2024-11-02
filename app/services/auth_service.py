"""
    This is the service layer for the authentication.
    It is responsible for the login and registration of the user.
    Furthermore, it is also responsible for generating the session token.
    Additionally, it is also responsible for handling the exceptions
"""
import base64
import hashlib
import time
import uuid
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta
from logging import getLogger
from os import urandom, getenv

import bcrypt
import pyotp
from bcrypt import hashpw, gensalt, checkpw
from flask import render_template, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_csrf_token, set_access_cookies

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
    def register(cls, user_data: dict):  # pylint: disable=C0116
        return UserRegistrationService.register_user(user_data)

    @classmethod
    def login(cls, email: str, plaintext_password: str):  # pylint: disable=C0116
        return UserLoginService.login_user(email, plaintext_password)

    @staticmethod
    def verify_token():  # pylint: disable=C0116
        return TokenService.verify_token()

    @staticmethod
    def generate_otp(email: str):  # pylint: disable=C0116
        return OTPService.generate_otp(email)

    @staticmethod
    def verify_otp(email: str, otp: str):  # pylint: disable=C0116
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
        front_end_verify_email_url = getenv(
            'LOCAL_FRONTEND_URL', '') + 'auth/verify-email/'
        is_email_exists = UserOperations.is_email_exists(
            user_data.get('email')
        )
        if is_email_exists:
            raise EmailAlreadyTaken('Email already taken.')
        salt = gensalt(rounds=16).decode('utf=8')
        hashed_password = hashpw(user_data.get('password').encode(
            'utf-8'), salt.encode('utf-8')).decode('utf-8')
        verification_token = (
            urlsafe_b64encode(urandom(128))
            .decode('utf-8').rstrip('=')
        )
        email = user_data.get('email')
        firstname = str(user_data.get('firstname')).capitalize()
        lastname = str(user_data.get('lastname')).capitalize()
        date_of_birth = user_data.get('date_of_birth')

        new_user_data = {
            'uuid': uuid.uuid4().bytes,
            'salt': salt,
            'hashed_password': hashed_password,
            'verification_token': verification_token,
            'verification_expiry': datetime.now() + timedelta(days=2),
            'verified_account': False,
            'username': email.split('@')[0],
            'email': email,
            'firstname': firstname,
            'lastname': lastname,
            'date_of_birth': date_of_birth,
            'creation_date': datetime.now(),
            'is_admin': user_data.get('is_admin')
        }

        UserOperations.create_new_user(new_user_data)
        message = render_template(
            "auth/welcome.html",
            verification_url=f"{front_end_verify_email_url}{verification_token}",
            user_name=user_data.get('email'))
        send_mail(
            message=message,
            email=user_data.get('email'),
            subject="VoteVoyage Onboarding 🎉"
        )


class UserLoginService:  # pylint: disable=R0903
    """ This class is responsible for the user login service. """
    @staticmethod
    def login_user(email, plaintext_password):  # pylint: disable=C0116
        user_hashed_password, is_verified = UserOperations.login(email)
        if not is_verified:
            raise AccountNotVerifiedException('Account not verified.')
        is_password_matched = checkpw(
            plaintext_password.encode('utf-8'),
            user_hashed_password.encode('utf-8'))
        if not is_password_matched:
            raise PasswordIncorrectException('Password incorrect.')
        OTPService.generate_otp(email)


class PasswordService:  # pylint: disable=R0903
    """ This class is responsible for the password service. Including the
    password reset and password update. """
    @staticmethod
    def hash_password(password):  # pylint: disable=C0116
        return hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

    @staticmethod
    def check_password(plaintext_password, hashed_password):  # pylint: disable=C0116
        return checkpw(plaintext_password.encode('utf-8'), hashed_password.encode('utf-8'))


class OTPService:  # pylint: disable=R0903
    """ This class is responsible for the OTP service. """
    @staticmethod
    def generate_otp(email):  # pylint: disable=C0116
        seed = f"{getenv('TOTP_SECRET_KEY')}{int(time.time())}"
        seven_digit_otp = pyotp.TOTP(
            base64.b32encode(bytes.fromhex(seed))
            .decode('UTF-8'), digits=7, interval=300, digest=hashlib.sha256).now()
        otp_expiry: datetime = datetime.now() + timedelta(minutes=5)
        OtpOperations.set_otp(email, seven_digit_otp, otp_expiry)
        otp_template = render_template(
            "auth/one-time-password.html",
            otp=seven_digit_otp, user_name=email)
        send_mail(email, otp_template,  "Your OTP Verification code")

    @staticmethod
    def verify_otp(email: str, otp: str):  # pylint: disable=C0116
        if not email or not otp:
            raise ValueError("Email and OTP are required.")
        is_user_exists = UserOperations.is_email_exists(email)
        if not is_user_exists:
            raise EmailNotFoundException('Email not found.')

        otp_secret, otp_expiry, user_id = OtpOperations.get_otp(email=email)

        if otp_secret is None or otp_expiry is None:
            raise OTPExpiredException("OTP has expired.")

        if otp_expiry < datetime.now():
            OtpOperations.invalidate_otp(email)
            raise OTPExpiredException("OTP has expired.")

        if int(otp_secret) != int(otp):
            OtpOperations.invalidate_otp(email)
            raise OTPIncorrectException("Incorrect OTP.")
        return user_id



class SendMailService:  # pylint: disable=R0903
    """ This class is responsible for the send mail service. """
    @staticmethod
    def send_mail(message, email, subject):  # pylint: disable=C0116
        return send_mail(message=message, email=email, subject=subject)


class TokenService:  # pylint: disable=R0903
    """ This class is responsible for the token verification service. """

    @staticmethod
    @jwt_required(locations=['cookies', 'headers'])
    def verify_token():  # pylint: disable=C0116
        return {'code': 'success', 'message': 'JWT Identity verified.'}, 200

    @staticmethod
    def generate_jwt_csrf_token(email, user_id):  # pylint: disable=C0116
        # Generate access token
        access_token = create_access_token(
            identity={'email': email, 'user_id': user_id},
            additional_claims={'csrf': True}
        )

        # Use with app context to ensure proper token handling
        with current_app.app_context():
            # Set the access token in cookies
            response = current_app.make_response('')
            set_access_cookies(response, access_token)
            # Now get the CSRF token
            csrf_token = get_csrf_token(access_token) # This returns boolean instead of bytes-like object or a string

        return access_token, csrf_token


class SessionTokenService:  # pylint: disable=R0903
    """ This class is responsible for the session token service. """
    @staticmethod
    def generate_session_token(email, user_id):  # pylint: disable=C0116
        return create_access_token(identity={'email': email, 'user_id': user_id})


class ForgotPasswordService:
    """ This class is responsible for the forgot password service. """
    @staticmethod
    def send_forgot_password_link(email):  # pylint: disable=C0116
        front_end_forgot_password_url = getenv(
            'LOCAL_FRONTEND_URL', '') + '/reset-password/'
        reset_token = base64.b64encode(urandom(128)).decode('utf-8')
        reset_expiry = datetime.now() + timedelta(minutes=60)
        reset_token, first_name = ForgotPasswordOperations.send_forgot_password_link(
            email, reset_token, reset_expiry)
        reset_password_url = front_end_forgot_password_url + reset_token
        SendMailService.send_mail(
            email=email,
            subject="Reset Password",
            message=render_template(
                "auth/forgot-password.html",
                reset_password_url=reset_password_url,
                user_name=first_name
            )
        )

    @staticmethod
    def verify_forgot_password_token(token, new_password):  # pylint: disable=C0116
        salt = bcrypt.gensalt(rounds=16).decode('utf=8')
        new_hashed_password = (bcrypt.hashpw(new_password.encode('utf-8'), salt.encode('utf-8'))
                           .decode('utf-8'))
        return PasswordOperations.verify_forgot_password_token(
            token,
            new_hashed_password,
            salt
        )


class EmailVerificationService:
    """ This class is responsible for the email verification service. """
    @staticmethod
    def verify_email(token):  # pylint: disable=C0116
        result = EmailVerificationOperations.verify_email(token)
        if result != 'email_verified':
            email = result
            EmailVerificationService.resend_email_verification(email=email)
        return result

    @staticmethod
    def resend_email_verification(email):  # pylint: disable=C0116
        verification_token = base64.b64encode(
            urandom(24)).decode('utf-8')
        verification_expiry = datetime.now() + timedelta(minutes=2880)
        EmailVerificationOperations.resend_email_verification(
            email,
            verification_expiry,
            verification_token
        )
        verification_url = getenv(
            'LOCAL_FRONTEND_URL', '') + getenv('API_VERIFY_EMAIL', '') + verification_token
        verification_template = render_template(
            "auth/welcome.html",
            verification_url=verification_url,
            user_name=email
        )
        SendMailService.send_mail(
            email=email, subject="Verify your email",
            message=verification_template
        )
