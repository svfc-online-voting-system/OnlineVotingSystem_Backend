""" Schema for voting event query for structured validation of the retrieval process. """

from marshmallow import Schema, fields, post_load, validate


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


class GetVotingEventQuerySchema(Schema):
    """Query Schema for fetching a voting event"""

    uuid = fields.Str(required=True)
    event_type = fields.String(
        required=False,
        validate=validate.OneOf(["poll", "election"]),
        load_default="poll",
    )

    @post_load
    def remove_hyphens(self, data, **kwargs):  # pylint: disable=unused-argument
        """Remove hyphens from the uuid"""
        data["uuid"] = data["uuid"].replace("-", "")
        return data


class GetVotingStatisticsQuerySchema(GetVotingEventQuerySchema):
    """Query Schema for fetching voting statistics"""
