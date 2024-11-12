""" Schema for voting event query for structured validation of the retrieval process. """

from marshmallow import Schema, fields, validate


class VotingEventQuerySchema(Schema):
    """
    This schema contains the schema validation for the voting event query.
    """

    voting_event_type = fields.String(
        required=False,
        validate=validate.OneOf(["poll", "election", "all"]),
        load_default="all",
    )
    voting_status = fields.String(
        required=False,
        validate=validate.OneOf(
            ["upcoming", "active", "completed", "cancelled", "all"]
        ),
        load_default="all",
    )
