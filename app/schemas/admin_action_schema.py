""" Schema validation for admin operations. """

from marshmallow import Schema, fields, validate


class ApproveVotingEventSchema(Schema):
    """Schema for validating the approve voting event request data"""

    voting_event_id = fields.Integer(
        required=True,
        validate=validate.Range(min=1),
    )


class VotingEventQuerySchema(Schema):
    """Schema for validating the query parameters for voting event retrieval"""

    voting_event_type = fields.String(
        required=False,
        validate=validate.OneOf(["poll", "electoral", "all"]),
        default="all",
    )
    voting_status = fields.String(
        required=False,
        validate=validate.OneOf(
            ["upcoming", "active", "completed", "cancelled", "all"]
        ),
        default="all",
    )
