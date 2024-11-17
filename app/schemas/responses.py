""" Schema / Shape of data that it expects to receive. """

from marshmallow import Schema, fields


class ApiResponse(Schema):
    """This class contains the schema for the API response."""

    code = fields.Str(required=True)
    message = fields.Str(required=True)
