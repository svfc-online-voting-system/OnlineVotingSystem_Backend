""" This module contains the schema validation for the authentication endpoints. """
from datetime import date
from marshmallow import Schema, fields, post_load, validate, ValidationError
from logging import getLogger

logger = getLogger(__name__)


class SignUpSchema(Schema):
    """ Schema represents the shape of data that it expects to receive. """
    firstname = fields.Str(
        required=True,
        validate=validate.Length(min=1),
        error_messages={
            'required': 'First name is required',
            'validator_failed': 'First name is invalid'
        }
    )
    lastname = fields.Str(
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
    def validate_age(self, data, **kwargs):
        """ This will check if the user is of legal age. """
        logger.debug(f"Validating age for data: {data}")
        dob = data.get('date_of_birth')
        
        if not dob:
            logger.debug("Date of birth is missing")
            raise ValidationError('Date of birth is required')
        
        logger.debug(f"Date of birth: {dob}, Type: {type(dob)}")
        
        today = date.today()
        logger.debug(f"Today's date: {today}")
        
        # Calculate age
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        logger.debug(f"Calculated age: {age}")
        
        if age < 18:
            logger.debug("User is under 18")
            raise ValidationError('User must be at least 18 years old')
        
        logger.debug("Age validation passed")
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
