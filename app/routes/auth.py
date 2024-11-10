""" This module contains the routes for the authentication of users. """

from logging import getLogger

from flask import Blueprint, request, Response
from flask_jwt_extended import (
    get_jwt_identity,
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
auth_blueprint = Blueprint("auth", __name__)
auth_service = AuthService()

auth_blueprint.register_error_handler(
    PasswordIncorrectException, handle_password_incorrect_exception
)
auth_blueprint.register_error_handler(
    AccountNotVerifiedException, handle_account_not_verified_exception
)
auth_blueprint.register_error_handler(EmailNotFoundException, handle_email_not_found)
auth_blueprint.register_error_handler(OTPExpiredException, handle_otp_expired_exception)
auth_blueprint.register_error_handler(
    OTPIncorrectException, handle_otp_incorrect_exception
)
auth_blueprint.register_error_handler(
    PasswordResetExpiredException, handle_password_reset_expired_exception
)
auth_blueprint.register_error_handler(
    PasswordResetLinkInvalidException, handle_password_reset_link_invalid_exception
)
auth_blueprint.register_error_handler(EmailAlreadyTaken, handle_email_already_taken)
auth_blueprint.register_error_handler(
    NoAuthorizationError, handle_no_authorization_error
)


@auth_blueprint.route(rule="/v1/auth/create-account", methods=["POST"])
@jwt_required(optional=True)
def create_account() -> Response:
    """This is the route for creating an account."""
    sign_up_schema = SignUpSchema()
    data = request.json
    validated_registration_data = sign_up_schema.load(data)  # type: ignore
    auth_service_create_account = AuthService()
    auth_service_create_account.register(validated_registration_data)  # type: ignore
    return set_response(
        200, {"code": "success", "message": "Open your email for verification."}
    )


@auth_blueprint.route(rule="/v1/auth/login", methods=["POST"])
@jwt_required(optional=True)
def login() -> Response:
    """This is the route for logging in."""
    data = request.json
    login_schema = LoginSchema()
    valid_user_data = login_schema.load(data)  # type: ignore
    auth_service_login = AuthService()
    auth_service_login.login(
        valid_user_data.get("email"), valid_user_data.get("password")  # type: ignore
    )
    return set_response(
        200, {"code": "otp_sent", "message": "OTP has been sent to your email."}
    )


@auth_blueprint.route(rule="/v1/auth/logout", methods=["POST"])
def logout() -> Response:
    """This is the route for logging out."""
    response = set_response(
        200, {"code": "success", "message": "Logged out successfully."}
    )
    unset_access_cookies(response)
    unset_refresh_cookies(response)
    unset_jwt_cookies(response)
    return response


@auth_blueprint.route(rule="/v1/auth/verify-jwt-identity", methods=["GET"])
@jwt_required(optional=False)
def verify_jwt_identity() -> Response:
    """This is the route for verifying the JWT identity."""
    try:
        get_jwt_identity()
        return set_response(200, {"code": "success", "message": "Token Verified"})
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
            401, {"code": "invalid_token", "message": "Invalid authentication token."}
        )


@auth_blueprint.route(rule="/v1/auth/verify-token-reset-password", methods=["PATCH"])
@jwt_required(optional=True)
def verify_token_reset_password():
    """Function for handling token verification for password reset."""
    data = request.json
    reset_password_schema = ResetPasswordSubmissionSchema()
    validated_data = reset_password_schema.load(data)  # type: ignore
    token = validated_data.get("token")  # type: ignore
    new_password = validated_data.get("new_password")  # type: ignore
    auth_service_token = AuthService()
    if auth_service_token.verify_forgot_password_token(token, new_password):
        return set_response(200, {"code": "success", "message": "Token Verified"})
    return set_response(
        401, {"code": "unauthorized", "message": "Unauthorized access."}
    )


@auth_blueprint.route(rule="/v1/auth/forgot-password", methods=["PATCH"])
@jwt_required(optional=True)
def forgot_password():
    """Function for handling forgot password."""
    data = request.json
    forgot_password_schema = ForgotPasswordSchema()
    validated_data = forgot_password_schema.load(data)  # type: ignore
    email = validated_data.get("email")  # type: ignore
    auth_service_forgot_password = AuthService()
    if auth_service_forgot_password.send_forgot_password_link(email):
        return set_response(
            200, {"code": "success", "message": "Password reset link sent"}
        )
    return set_response(
        401, {"code": "unauthorized", "message": "Unauthorized access."}
    )


@auth_blueprint.route(rule="/v1/auth/otp-verification", methods=["PATCH"])
@jwt_required(optional=True)
def otp_verification():
    """Function for handling otp verification"""
    data = request.json
    otp_submission_schema = OTPSubmissionSchema()
    validated_data = otp_submission_schema.load(data)  # type: ignore
    email = validated_data.get("email")  # type: ignore
    otp = validated_data.get("otp_code")  # type: ignore
    auth_service_otp = AuthService()
    user_id = auth_service_otp.verify_otp(email=email, otp=otp)  # type: ignore

    token_service = TokenService()
    access_token, refresh_token = (  # pylint: disable=unused-variable
        token_service.generate_jwt_csrf_token(email=email, user_id=user_id)
    )
    response = set_response(200, {"code": "success", "message": "OTP Verified"})
    set_access_cookies(response, access_token)
    set_refresh_cookies(response, refresh_token)

    return response


@auth_blueprint.route(rule="/v1/auth/generate-otp", methods=["PATCH"])
@jwt_required(optional=True)
def generate_otp() -> Response:
    """Function for handling otp generation.
    The use-case of this is when the user want to resend
    the otp code that previously sent to the user."""
    data = request.json
    otp_generation_schema = OTPGenerationSchema()
    validated_data = otp_generation_schema.load(data)  # type: ignore
    email = validated_data.get("email")  # type: ignore
    auth_service_otp = AuthService()
    if auth_service_otp.generate_otp(email=email):  # type: ignore
        return set_response(200, {"code": "success", "message": "OTP Generated"})
    return set_response(
        401, {"code": "unauthorized", "message": "Unauthorized access."}
    )


@auth_blueprint.route("/v1/auth/verify-email/<string:token>", methods=["GET"])
def verify_email(token: str) -> Response:
    """Function for handling email verification."""
    if len(token) != 171 or not token:
        return set_response(
            400, {"code": "invalid_request", "message": "Bad Request: Invalid token."}
        )
    auth_service_verify_email = AuthService()
    if auth_service_verify_email.verify_email(token):
        return set_response(200, {"code": "success", "message": "Email Verified"})
    return set_response(
        401, {"code": "unauthorized", "message": "Unauthorized access."}
    )


@auth_blueprint.route(rule="/v1/auth/resend-verification-email", methods=["PATCH"])
@jwt_required(optional=True)
def resend_verification_email() -> Response:
    """Function for handling email verification."""
    data = request.json
    email_verification_schema = EmailVerificationSchema()
    validated_data = email_verification_schema.load(data)  # type: ignore
    email = validated_data.get("email")  # type: ignore
    if not email:
        raise ValueError("Invalid data format")
    auth_service_resend_verification_email = AuthService()
    if auth_service_resend_verification_email.resend_email_verification(email):
        return set_response(
            200, {"code": "success", "message": "Email Verification Sent"}
        )
    return set_response(
        401, {"code": "unauthorized", "message": "Unauthorized access."}
    )
