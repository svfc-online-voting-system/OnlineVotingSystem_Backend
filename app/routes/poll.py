""" Routes for poll related endpoint """

from logging import getLogger

from flask import Blueprint, request
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from flask_jwt_extended.exceptions import NoAuthorizationError

from app.exception.voting_event_exception import VotingEventDoesNotExists
from app.schemas.poll_voting_event_schema import PollVotingEventSchema
from app.services.poll_service import PollService
from app.utils.error_handlers.jwt_error_handlers import handle_no_authorization_error
from app.utils.error_handlers.voting_event_error_handlers import (
    handle_voting_event_does_not_exists,
)
from app.utils.response_util import set_response

logger = getLogger(name=__name__)
poll_blueprint = Blueprint("poll", __name__)

poll_blueprint.register_error_handler(
    NoAuthorizationError, handle_no_authorization_error
)
poll_blueprint.register_error_handler(
    VotingEventDoesNotExists, handle_voting_event_does_not_exists
)


@poll_blueprint.route(rule="/v1/editor/add-poll", methods=["POST"])
@jwt_required(optional=False)
def add_poll():
    """Add a new poll for the user"""
    data = request.json
    new_poll_voting_event_schema = PollVotingEventSchema()
    new_poll_voting_data = new_poll_voting_event_schema.load(data)  # type: ignore
    new_poll_voting_data["created_by"] = get_jwt().get("sub").get("user_id")  # type: ignore
    poll_service = PollService()
    poll_service.add_new_poll(new_poll_voting_data)
    return set_response(
        201, {"code": "success", "message": "The poll has been created."}
    )


@poll_blueprint.route(rule="/v1/editor/delete-poll", methods=["DELETE"])
@jwt_required(locations=["cookies", "headers"])
def delete_poll():
    """This route is used to delete a poll."""
    data = request.json
    if data is None:
        return set_response(
            400,
            {"code": "invalid_request", "message": "Bad Request: No data provided."},
        )
    poll_ids = data.get("poll_id")
    user_id = get_jwt().get("sub").get("user_id")  # type: ignore
    poll_service = PollService()
    poll_service.delete_polls(poll_ids, user_id)
    return set_response(
        200, {"code": "success", "message": "The poll has been deleted."}
    )


@poll_blueprint.route(rule="/v1/editor/rename-poll", methods=["PATCH"])
@jwt_required(locations=["cookies", "headers"])
def rename_poll():
    """This route is used to rename a poll."""
    data = request.json
    if data is None:
        return set_response(
            400,
            {"code": "invalid_request", "message": "Bad Request: No data provided."},
        )
    poll_id = data.get("poll_id")
    user_id = get_jwt().get("sub").get("user_id")  # type: ignore
    poll_service = PollService()
    poll_service.rename_poll_title(poll_id=poll_id, user_id=user_id)
    return set_response(
        200, {"code": "success", "message": "The poll has been renamed."}
    )


@poll_blueprint.route(rule="/v1/editor/get_poll_details", methods=["GET"])
@jwt_required(locations=["cookies", "headers"])
def get_poll_details():
    """This route is used to get the details of a poll."""
    data = request.json
    if data is None or not data.get("poll_id"):
        return set_response(
            400,
            {"code": "invalid_request", "message": "Bad Request: No data provided."},
        )
    user_id = get_jwt().get("sub").get("user_id")  # type: ignore
    poll_id = data.get("poll_id")
    poll_service = PollService()
    details = poll_service.get_poll_details(user_id, poll_id)
    return set_response(
        200,
        {
            "code": "success",
            "message": "Poll details retrieved successfully.",
            "data": details,
        },
    )


@poll_blueprint.route(rule="/v1/editor/add-option", methods=["POST"])
@jwt_required(locations=["cookies", "headers"])
def add_option():
    """This route is used to add a new option to a poll."""
    data = request.json
    if data is None:
        return set_response(
            400,
            {"code": "invalid_request", "message": "Bad Request: No data provided."},
        )
    user_id = get_jwt().get("sub").get("user_id")  # type: ignore
    poll_id = data.get("poll_id")
    option_text = data.get("option_text")
    poll_service = PollService()
    poll_service.add_option(poll_id=poll_id, user_id=user_id, option_text=option_text)
    return set_response(
        201, {"code": "success", "message": "The option has been added."}
    )


@poll_blueprint.route(rule="/v1/editor/edit-option", methods=["PATCH"])
@jwt_required(locations=["cookies", "headers"])
def edit_option():
    """This route is used to edit a poll option."""
    data = request.json
    if data is None:
        return set_response(
            400,
            {"code": "invalid_request", "message": "Bad Request: No data provided."},
        )
    option_id = data.get("option_id")
    new_option_text = data.get("new_option_text")
    user_id = get_jwt().get("sub").get("user_id")  # type: ignore
    poll_service = PollService()
    poll_service.edit_option(option_id, new_option_text, user_id)
    return set_response(
        200, {"code": "success", "message": "The option has been edited."}
    )


@poll_blueprint.route(rule="/v1/user/cast-poll-vote", methods=["POST"])
@jwt_required(locations=["cookies", "headers"])
def cast_poll_vote():
    """This route is used to cast a vote."""
    data = request.json
    if data is None:
        return set_response(
            400,
            {"code": "invalid_request", "message": "Bad Request: No data provided."},
        )
    event_id = data.get("event_id")
    option_id = data.get("option_id")
    poll_service = PollService()
    poll_service.cast_poll_vote(
        event_id=event_id, option_id=option_id, user_id=get_jwt_identity()
    )
    return set_response(201, {"code": "success", "message": "The vote has been cast."})


@poll_blueprint.route(rule="/v1/user/uncast-poll-vote", methods=["POST"])
@jwt_required(locations=["cookies", "headers"])
def uncast_poll_vote():
    """This route is used to uncast a vote."""
    data = request.json
    if data is None:
        return set_response(
            400,
            {"code": "invalid_request", "message": "Bad Request: No data provided."},
        )
    vote_info = data
    poll_service = PollService()
    poll_service.uncast_poll_vote(vote_info=vote_info)
    return set_response(
        201, {"code": "success", "message": "The vote has been uncast."}
    )


@poll_blueprint.route(rule="/v1/user/change-vote", methods=["PATCH"])
@jwt_required(locations=["cookies", "headers"])
def change_vote():
    """This route is used to change a vote."""
    data = request.json
    if data is None:
        return set_response(
            400,
            {"code": "invalid_request", "message": "Bad Request: No data provided."},
        )
    vote_info = request.json
    poll_service = PollService()
    poll_service.change_vote(vote_info=vote_info)
    return set_response(
        200, {"code": "success", "message": "The vote has been changed."}
    )
