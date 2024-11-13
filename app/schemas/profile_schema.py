""" Wraps the validation schema for the profile routes. """

from marshmallow import Schema, fields, validate


class ProfileSchema(Schema):
    """Schema for the profile routes."""

    first_name = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3),
            validate.Length(max=75),
        ],
    )
    last_name = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3),
            validate.Length(max=75),
        ],
    )
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3),
            validate.Length(max=75),
        ],
    )
