""" This module contains the schema validation for the authentication endpoints. """
from datetime import date
from marshmallow import Schema, fields, post_load, validate, ValidationError


class SignUpSchema(Schema):
    """ The Schema represents the shape of data that it expects to receive. """
    first_name = fields.Str(
        required=True,
        validate=validate.Length(min=1),
        error_messages={
            'required': 'First name is required',
            'validator_failed': 'First name is invalid'
        }
    )
    last_name = fields.Str(
        required=True,
        validate=validate.Length(min=1),
        error_messages={
            'required': 'Last name is required',
            'validator_failed': 'Last name is invalid'
        }
    )
    email = fields.Str(
        required=True,
        validate=validate.Email(),
        error_messages={
            'required': 'Email is required',
            'validator_failed': 'Email is invalid'
        }
    )
    password = fields.Str(
        required=True,
        validate=[
            validate.Length(min=8),
            validate.Regexp(regex='^[a-zA-Z0-9]*$')])
    date_of_birth = fields.Date(
        required=True,
        error_messages={
            'required': 'Date of birth is required',
            'invalid': 'Date of birth is invalid. Please use the format YYYY-MM-DD.'
        }
    )
    @post_load
    def validate_age(self, data):
        """ This will check if the user is of legal age. """
        dob = data.get('date_of_birth')
        if not dob:
            raise ValidationError('Date of birth is required')
        today = date.today()
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        if age < 18:
            raise ValidationError('User must be at least 18 years old')
        return data


class LoginSchema(Schema):
    """ Login Schema represents the shape of data that it expects to receive. """
    email = fields.Str(
        required=True,
        validate=validate.Email(),
        error_messages={
            'required': 'Email is required',
            'validator_failed': 'Email is invalid'
        }
    )
    password = fields.Str(
        required=True,
        validate=[
            validate.Length(min=8)
        ],
        error_messages={
            'required': 'Password is required',
            'validator_failed': 'Password is invalid'
        }
    )
