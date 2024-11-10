""" This module contains the schema validation for the authentication endpoints. """

from datetime import date

from marshmallow import Schema, fields, post_load, validate, ValidationError


class EmailBaseSchema(Schema):
    """This class contains the schema validation for the email field. This can be reused for multiple"""

    email = fields.Str(
        required=True,
        validate=validate.Email(error="Email is invalid"),
    )


class PasswordBaseSchema(Schema):
    """This class contains the schema validation for the password field. This can be reused for multiple"""

    password = fields.Str(
        required=True,
        validate=[validate.Length(min=8), validate.Regexp(regex="^[a-zA-Z0-9]*$")],
    )


class SignUpSchema(EmailBaseSchema, PasswordBaseSchema):
    """The Schema represents the shape of data that it expects to receive."""

    firstname = fields.Str(
        required=True,
        validate=validate.Length(min=1),
    )
    lastname = fields.Str(
        required=True,
        validate=validate.Length(min=1),
    )
    date_of_birth = fields.Date(
        required=True,
        error_messages={
            "required": "Date of birth is required",
            "invalid": "Date of birth is invalid. Please use the format YYYY-MM-DD.",
        },
    )

    # noinspection PyUnusedLocal
    @post_load
    def validate_age(self, data, **kwargs):  # pylint: disable=unused-argument
        """This will check if the user is of legal age."""
        dob = data.get("date_of_birth")
        if not dob:
            raise ValidationError("Date of birth is required")
        today = date.today()
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        if age < 18:
            raise ValidationError("User must be at least 18 years old")
        return data


class LoginSchema(EmailBaseSchema, PasswordBaseSchema):
    """Login Schema represents the shape of data that it expects to receive."""


class ResetPasswordSchema(EmailBaseSchema):
    """Reset Password Schema represents the shape of data that it expects to receive."""


class OTPSubmissionSchema(EmailBaseSchema):
    """OTP Verification Schema represents the shape of data that it expects to receive."""

    otp_code = fields.Str(
        required=True,
        validate=validate.Length(min=7, max=7),
    )


class ForgotPasswordSchema(EmailBaseSchema):
    """Forgot Password Schema represents the shape of data that it expects to receive."""


class ResetPasswordSubmissionSchema(Schema):
    """Reset Password Submission Schema represents the shape of data that it expects to receive."""

    new_password = fields.Str(
        required=True,
        validate=[validate.Length(min=8), validate.Regexp(regex="^[a-zA-Z0-9]*$")],
    )

    token = (
        fields.Str(
            required=True,
            validate=validate.Length(min=171, max=171),
        ),
    )


class OTPGenerationSchema(EmailBaseSchema):
    """OTP Generation Schema represents the shape of data that it expects to receive."""


class EmailVerificationSchema(EmailBaseSchema):
    """Email Verification Schema represents the shape of data that it expects to receive."""
