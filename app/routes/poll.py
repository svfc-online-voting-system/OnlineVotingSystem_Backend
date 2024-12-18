""" Routes for poll related endpoint """

# pylint: disable=missing-function-docstring, missing-class-docstring

from functools import wraps
from logging import getLogger

from flask.views import MethodView
from flask_smorest import Blueprint
from flask_jwt_extended import (
    jwt_required,
    get_jwt,
)
from flask_jwt_extended.exceptions import NoAuthorizationError

from app.exception.voting_event_exception import VotingEventDoesNotExists
from app.schemas.poll_voting_event_schema import (
    OptionSchema,
    PollVotingEventSchema,
    DeletePollEventsSchema,
)
from app.schemas.responses import ApiResponse
from app.services.poll_service import PollService
from app.utils.error_handlers.jwt_error_handlers import handle_no_authorization_error
from app.utils.error_handlers.voting_event_error_handlers import (
    handle_voting_event_does_not_exists,
)
from app.utils.response_util import set_response

logger = getLogger(name=__name__)
poll_blp = Blueprint(
    "poll",
    __name__,
    url_prefix="/api/v1/poll",
    description="Polls API endpoints for VoteVoyage",
)


def user_role_and_user_id_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            user_id = get_jwt().get("sub", {}).get("user_id")
            if not user_id:
                return set_response(
                    401, {"code": "unauthorized", "message": "User access required"}
                )
            return fn(*args, **kwargs)

        return decorator

    return wrapper


@poll_blp.route("/editor/add-poll")
class AddPoll(MethodView):

    @poll_blp.arguments(PollVotingEventSchema)
    @poll_blp.response(201, ApiResponse)
    @poll_blp.doc(
        description="Add a new poll for the give user id.",
        responses={
            "422": {"description": "Validation Error"},
            "401": {"description": "Unauthorized"},
        },
    )
    @jwt_required(False)
    @user_role_and_user_id_required()
    def post(self, data, user_id):
        data["created_by"] = user_id
        poll_service = PollService()
        poll_service.add_new_poll(data)
        return set_response(
            201, {"code": "success", "message": "The poll has been created."}
        )


@poll_blp.route("/editor/delete-polls")
class DeletePoll(MethodView):
    @poll_blp.arguments(DeletePollEventsSchema)
    @poll_blp.response(200, ApiResponse)
    @poll_blp.doc(
        description="Delete a poll for the given user id and poll id",
        responses={
            "422": {"description": "Validation Error"},
            "404": {"description": "Voting event does not exists"},
            "401": {"description": "Unauthorized"},
        },
    )
    @jwt_required(False)
    @user_role_and_user_id_required()
    def delete(self, data, user_id):
        poll_service = PollService()
        poll_service.delete_polls(data.get("poll_ids"), user_id)
        return set_response(
            200, {"code": "success", "message": "The poll has been deleted."}
        )


@poll_blp.route("/editor/get-polls")
class GetPolls(MethodView):
    @poll_blp.response(200, ApiResponse)
    @poll_blp.doc(
        description="Get all the polls for the given user id",
        responses={
            "401": {"description": "Unauthorized"},
        },
    )
    @jwt_required(False)
    @user_role_and_user_id_required()
    def get(self, user_id):
        poll_service = PollService()
        polls = poll_service.get_polls(user_id)
        return set_response(
            200,
            {
                "code": "success",
                "message": "Polls retrieved successfully.",
                "data": polls,
            },
        )


@poll_blp.route("/editor/rename-poll")
class RenamePoll(MethodView):
    @poll_blp.arguments(PollVotingEventSchema)
    @poll_blp.response(200, ApiResponse)
    @poll_blp.doc(
        description="Rename a poll title, this is for the owner of the poll",
        responses={
            "422": {"description": "Validation Error"},
            "404": {"description": "Voting event does not exists"},
            "401": {"description": "Unauthorized"},
        },
    )
    @jwt_required(False)
    @user_role_and_user_id_required()
    def patch(self, data, user_id):
        poll_id = data.get("poll_id")
        poll_service = PollService()
        poll_service.rename_poll_title(poll_id=poll_id, user_id=user_id)
        return set_response(
            200, {"code": "success", "message": "The poll has been renamed."}
        )


@poll_blp.route("/editor/get-poll-details")
class GetPollDetails(MethodView):
    @poll_blp.response(200, ApiResponse)
    @poll_blp.doc(
        description="Get the details of a poll, this is for the owner of the poll",
        responses={
            "404": {"description": "Voting event does not exists"},
            "401": {"description": "Unauthorized"},
        },
    )
    @jwt_required(False)
    @user_role_and_user_id_required()
    def get(self, data, user_id):
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


@poll_blp.route("/editor/add-option")
class AddOption(MethodView):

    @poll_blp.arguments(OptionSchema)
    @poll_blp.response(201, ApiResponse)
    @poll_blp.doc(
        description="Add a new option to a poll, this is for the owner of the poll",
        responses={
            "404": {"description": "Voting event does not exists"},
            "401": {"description": "Unauthorized"},
        },
    )
    @jwt_required(False)
    @user_role_and_user_id_required()
    def post(self, data, user_id):
        poll_id = data.get("poll_id")
        option_text = data.get("option")
        poll_service = PollService()
        poll_service.add_option(poll_id, user_id, option_text)
        return set_response(
            201, {"code": "success", "message": "The option has been added."}
        )


@poll_blp.route("/editor/edit-option")
class EditOption(MethodView):

    @poll_blp.arguments(OptionSchema)
    @poll_blp.response(200, ApiResponse)
    @poll_blp.doc(
        description="Edit a poll option, this is for the owner of the poll",
        responses={
            "404": {"description": "Voting event does not exists"},
            "401": {"description": "Unauthorized"},
        },
    )
    @jwt_required(False)
    @user_role_and_user_id_required()
    def patch(self, data, user_id):
        option_id = data.get("option_id")
        new_option_text = data.get("new_option_text")
        poll_service = PollService()
        poll_service.edit_option(option_id, new_option_text, user_id)
        return set_response(
            200, {"code": "success", "message": "The option has been edited."}
        )


@poll_blp.route("/user/get-options")
class GetOptions(MethodView):
    @poll_blp.response(200, ApiResponse)
    @poll_blp.doc(
        description="Get the options for a poll",
        responses={
            "404": {"description": "Voting event does not exists"},
            "401": {"description": "Unauthorized"},
        },
    )
    @jwt_required(False)
    def get(self, data):
        poll_id = data.get("poll_id")
        poll_service = PollService()
        options = poll_service.get_options(poll_id)
        return set_response(
            200,
            {
                "code": "success",
                "message": "Options retrieved successfully.",
                "data": options,
            },
        )


poll_blp.register_error_handler(NoAuthorizationError, handle_no_authorization_error)
poll_blp.register_error_handler(
    VotingEventDoesNotExists, handle_voting_event_does_not_exists
)
