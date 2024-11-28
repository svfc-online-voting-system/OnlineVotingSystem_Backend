""" Schema for respondents who are casting their vote. """

from marshmallow import Schema, fields


class PollCastingSchema(Schema):
    """Schema for casting a vote."""

    event_uuid = fields.Str(required=True)
    poll_option_id = fields.Integer(required=True)


class UnCastPollCastingSchema(Schema):
    """Schema for uncasting a vote."""

    event_id = fields.Integer(required=True)
