""" This module contains the routes for the authentication of users. """

# pylint: disable=missing-function-docstring, missing-class-docstring

from logging import getLogger

from flask_smorest import Blueprint
from flask.views import MethodView
from flask_jwt_extended import (
    get_jwt,
    jwt_required,
    set_access_cookies,
    set_refresh_cookies,
    unset_access_cookies,
    unset_jwt_cookies,
    unset_refresh_cookies,
)
from flask_jwt_extended.exceptions import NoAuthorizationError
from jwt import ExpiredSignatureError, InvalidTokenError

from app.exception.authorization_exception import (
    EmailNotFoundException,
    OTPExpiredException,
    OTPIncorrectException,
    PasswordResetExpiredException,
    PasswordResetLinkInvalidException,
    EmailAlreadyTaken,
    PasswordIncorrectException,
    AccountNotVerifiedException,
)
from app.schemas.auth_forms_schema import (
    SignUpSchema,
    LoginSchema,
    OTPSubmissionSchema,
    ResetPasswordSubmissionSchema,
    OTPGenerationSchema,
    ForgotPasswordSchema,
    EmailVerificationSchema,
)
from app.schemas.responses import ApiResponse
from app.services.auth_service import AuthService
from app.services.token_service import TokenService
from app.utils.error_handlers.auth_error_handlers import (
    handle_account_not_verified_exception,
    handle_password_incorrect_exception,
    handle_otp_incorrect_exception,
    handle_otp_expired_exception,
    handle_email_not_found,
    handle_password_reset_expired_exception,
    handle_password_reset_link_invalid_exception,
    handle_email_already_taken,
)
from app.utils.error_handlers.jwt_error_handlers import handle_no_authorization_error
from app.utils.response_util import set_response

logger = getLogger(name=__name__)
auth_service = AuthService()


auth_blp = Blueprint(
    "auth", __name__, url_prefix="/api/v1/auth", description="Auth API for VoteVoyage"
)


@auth_blp.route("/create-account")
class AccountRegistration(MethodView):
    @auth_blp.arguments(SignUpSchema)
    @auth_blp.response(200, ApiResponse)
    @auth_blp.doc(
        description="Create new user account",
        responses={
            "400": {"description": "Email already taken"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(optional=True)
    def post(self, registration_data):
        auth_service.register(registration_data)
        return set_response(
            200, {"code": "success", "message": "Open your email for verification."}
        )


@auth_blp.route("/login")
class Login(MethodView):
    @auth_blp.arguments(LoginSchema)
    @auth_blp.response(200, ApiResponse)
    @auth_blp.doc(
        description="User login, OTP will be sent to the email address and the user will be logged in.",
        responses={
            "400": {"description": "Invalid credentials"},
            "401": {"description": "Account not verified"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(optional=True)
    def post(self, login_data):
        """Login user"""
        auth_service.login(login_data.get("email"), login_data.get("password"))
        return set_response(
            200, {"code": "otp_sent", "message": "OTP has been sent to your email."}
        )


@auth_blp.route("/logout")
class Logout(MethodView):
    @auth_blp.response(200, ApiResponse)
    @auth_blp.doc(
        description="Logout user, clearing cookies like access, refresh and jwt.",
        responses={"200": {"description": "Logged out successfully"}},
    )
    def post(self):
        response = set_response(
            200, {"code": "success", "message": "Logged out successfully."}
        )
        unset_access_cookies(response)
        unset_refresh_cookies(response)
        unset_jwt_cookies(response)
        return response


@auth_blp.route("/verify-jwt-identity")
class VerifyJWTIdentity(MethodView):
    @auth_blp.response(200, ApiResponse)
    @auth_blp.doc(
        description="Verify JWT identity",
        responses={
            "400": {"description": "Invalid token"},
            "401": {"description": "Unauthorized access"},
        },
    )
    @jwt_required(optional=False)
    def get(self):
        try:
            role = get_jwt().get("sub").get("role")  # type: ignore
            return set_response(200, {"code": "success", "message": role})
        except ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return set_response(
                401,
                {
                    "code": "token_expired",
                    "message": "Your session has expired. Please log in again.",
                },
            )
        except InvalidTokenError:
            logger.warning("Invalid JWT token")
            return set_response(
                401,
                {"code": "invalid_token", "message": "Invalid authentication token."},
            )


@auth_blp.route("/verify-token-reset-password")
class VerifyTokenResetPassword(MethodView):
    @auth_blp.arguments(ResetPasswordSubmissionSchema)
    @auth_blp.response(200, ApiResponse)
    @auth_blp.doc(
        description="Verify token for password reset. If token is valid, return a new token for the user.",
        responses={
            "400": {"description": "Invalid token"},
            "401": {"description": "Unauthorized access"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(optional=True)
    def patch(self, reset_password_data):
        token = reset_password_data.get("token")
        new_password = reset_password_data.get("new_password")
        auth_service.verify_forgot_password_token(token, new_password)
        return set_response(200, {"code": "success", "message": "Token Verified"})


@auth_blp.route("/forgot-password")
class ForgotPassword(MethodView):
    @auth_blp.arguments(ForgotPasswordSchema)
    @auth_blp.response(200, ApiResponse)
    @auth_blp.doc(
        description="Forgot password, send a password reset link to the email address.",
        responses={
            "400": {"description": "Invalid email"},
            "401": {"description": "Unauthorized access"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(optional=True)
    def patch(self, forgot_password_data):
        email = forgot_password_data.get("email")
        auth_service.send_forgot_password_link(email)
        return set_response(
            200, {"code": "success", "message": "Password reset link sent"}
        )


@auth_blp.route("/otp-verification")
class OTPVerification(MethodView):
    @auth_blp.arguments(OTPSubmissionSchema)
    @auth_blp.response(200, ApiResponse)
    @auth_blp.doc(
        description="OTP verification, verify the OTP sent to the user's email.",
        responses={
            "400": {"description": "Invalid OTP"},
            "401": {"description": "Unauthorized access"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(optional=True)
    def patch(self, otp_data):
        email = otp_data.get("email")
        otp = otp_data.get("otp_code")
        user_id, is_admin = auth_service.verify_otp(email, otp)
        role = "admin" if is_admin else "user"

        token_service = TokenService()
        access_token, refresh_token = (  # pylint: disable=unused-variable
            token_service.generate_jwt_csrf_token(email, user_id, role)
        )
        response = set_response(200, {"code": "success", "message": role})

        set_access_cookies(response, access_token)
        set_refresh_cookies(response, refresh_token)

        return response


@auth_blp.route("/generate-otp")
class GenerateOTP(MethodView):
    @auth_blp.arguments(OTPGenerationSchema)
    @auth_blp.response(200, ApiResponse)
    @auth_blp.doc(
        description="Generate OTP, send OTP to the user's email.",
        responses={
            "400": {"description": "Invalid email"},
            "401": {"description": "Unauthorized access"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(optional=True)
    def patch(self, otp_data):
        email = otp_data.get("email")
        auth_service.generate_otp(email)
        return set_response(200, {"code": "success", "message": "OTP Generated"})


@auth_blp.route("/verify-email/<string:token>")
class VerifyEmail(MethodView):
    @auth_blp.arguments(EmailVerificationSchema, location="view_args")
    @auth_blp.response(200, ApiResponse)
    @auth_blp.doc(
        description="Verify email using verification token",
        responses={
            "400": {"description": "Invalid token format"},
            "401": {"description": "Token verification failed"},
            "422": {"description": "Validation error"},
        },
    )
    def get(self, args):
        token = args["token"]
        auth_service_verify_email = AuthService()
        if auth_service_verify_email.verify_email(token):
            return set_response(
                200, {"code": "success", "message": "Email verified successfully"}
            )
        return set_response(
            401, {"code": "unauthorized", "message": "Token verification failed"}
        )


@auth_blp.route("/resend-verification-email")
class ResendVerificationEmail(MethodView):
    @auth_blp.arguments(EmailVerificationSchema)
    @auth_blp.response(200, ApiResponse)
    @auth_blp.doc(
        description="Resend verification email, send verification email to the user's email.",
        responses={
            "400": {"description": "Invalid email"},
            "401": {"description": "Unauthorized access"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(optional=True)
    def patch(self, resend_verification_email_data):
        email = resend_verification_email_data.get("email")
        auth_service_resend_verification_email = AuthService()
        auth_service_resend_verification_email.resend_email_verification(email)
        return set_response(
            200, {"code": "success", "message": "Email Verification Sent"}
        )


auth_blp.register_error_handler(
    PasswordIncorrectException, handle_password_incorrect_exception
)
auth_blp.register_error_handler(
    AccountNotVerifiedException, handle_account_not_verified_exception
)
auth_blp.register_error_handler(EmailNotFoundException, handle_email_not_found)
auth_blp.register_error_handler(OTPExpiredException, handle_otp_expired_exception)
auth_blp.register_error_handler(OTPIncorrectException, handle_otp_incorrect_exception)
auth_blp.register_error_handler(
    PasswordResetExpiredException, handle_password_reset_expired_exception
)
auth_blp.register_error_handler(
    PasswordResetLinkInvalidException, handle_password_reset_link_invalid_exception
)
auth_blp.register_error_handler(EmailAlreadyTaken, handle_email_already_taken)
auth_blp.register_error_handler(NoAuthorizationError, handle_no_authorization_error)
