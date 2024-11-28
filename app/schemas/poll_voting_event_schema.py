""" New polling event schema validation """

from datetime import datetime

from marshmallow import Schema, fields, post_load, validate, ValidationError


class PollVotingEventSchema(Schema):
    """This class contains the schema validation for the new polling event."""

    title = fields.Str(
        required=True,
        validate=validate.Length(min=3, max=255),
        error_messages={
            "required": "Title is required",
            "validator_failed": "Title is invalid",
        },
    )

    start_date = fields.DateTime(
        required=True,
        error_messages={
            "required": "Start date is required",
            "validator_failed": "Start date is invalid",
        },
    )
    end_date = fields.DateTime(
        required=True,
        error_messages={
            "required": "End date is required",
            "validator_failed": "End date is invalid",
        },
    )

    description = fields.Str(
        required=True,
        validate=validate.Length(min=3, max=21_844),
        error_messages={
            "required": "Description is required",
            "validator_failed": "Description is invalid",
        },
    )

    # noinspection PyUnusedLocal
    @post_load
    def validate_start_date(self, data, **kwargs):  # pylint: disable=unused-argument
        """This will check if the start date is in the future."""
        start_date = data.get("start_date")
        if not start_date:
            raise ValidationError("Start date is required")
        right_now = datetime.now()
        if start_date < right_now:
            raise ValidationError("Start date must be in the future")
        return data

    # noinspection PyUnusedLocal
    @post_load
    def validate_end_date(self, data, **kwargs):  # pylint: disable=unused-argument
        """This will check if the end date is after the start date."""
        start_date = data.get("start_date")
        end_date = data.get("end_date")
        right_now = datetime.now()
        if not end_date:
            raise ValidationError("End date is required")
        if end_date < start_date:
            raise ValidationError("End date must be after the start date")
        if end_date < right_now:
            raise ValidationError("End date must be in the future")
        return data


class DeletePollEventsSchema(Schema):
    """This class contains the schema validation for the delete polling events."""

    poll_ids = fields.List(
        fields.Int(
            required=True,
        ),
        required=True,
    )

    # noinspection PyUnusedLocal
    @post_load
    def validate_poll_id(self, data, **kwargs):  # pylint: disable=unused-argument
        """This will check if the poll id is a list."""
        poll_id = data.get("poll_id")
        if not poll_id:
            raise ValidationError("Poll ID is required")
        if not isinstance(poll_id, list):
            raise ValidationError("Poll ID must be a list")
        return data


class OptionSchema(Schema):
    """This class contains the schema validation for adding a new option to a poll."""

    poll_id = fields.Int(
        required=True,
        error_messages={
            "required": "Poll ID is required",
            "validator_failed": "Poll ID is invalid",
        },
    )

    option = fields.Str(
        required=True,
        validate=validate.Length(min=3, max=255),
        error_messages={
            "required": "Option is required",
            "validator_failed": "Option is invalid",
        },
    )
