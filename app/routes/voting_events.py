""" Wraps all the route that is related to a broad retrieval of voting events """

# pylint: disable=missing-function-docstring, missing-class-docstring

from functools import wraps
from logging import getLogger

from flask.views import MethodView
from flask_smorest import Blueprint
from flask_jwt_extended import get_jwt, jwt_required

from app.exception.voting_event_exception import VotingEventDoesNotExists
from app.schemas.responses import ApiResponse
from app.services.voting_event_service import VotingEventService
from app.schemas.voting_event_query import (
    GetVotingStatisticsQuerySchema,
    VotingEventQuerySchema,
    GetVotingEventQuerySchema,
)
from app.utils.error_handlers.voting_event_error_handlers import (
    handle_voting_event_does_not_exists,
)
from app.utils.response_util import set_response

voting_event_blp = Blueprint(
    "voting_events",
    __name__,
    url_prefix="/api/v1/voting-event",
    description="Voting events API endpoints for VoteVoyage",
)

logger = getLogger(name=__name__)


def auth_required():
    """Decorator to check if the user is authenticated."""

    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            get_jwt()
            return fn(*args, **kwargs)

        return decorator

    return wrapper


@voting_event_blp.route("/user/get-voting-event-by")
class GetVotingEventBy(MethodView):
    @voting_event_blp.arguments(VotingEventQuerySchema, location="query")
    @voting_event_blp.response(200, ApiResponse)
    @voting_event_blp.doc(
        description="Retrieves voting events based on query parameters.",
        responses={
            "200": {"description": "Voting events retrieved successfully"},
            "401": {"description": "Unauthorized access"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(False)
    def get(self, query_params):
        get_jwt()
        voting_event_type = query_params.get("voting_event_type")
        voting_status = query_params.get("voting_status")

        voting_events = VotingEventService.get_voting_events_by(
            voting_event_type, voting_status
        )

        return set_response(200, {"code": "success", "voting_events": voting_events})


@voting_event_blp.route("/user/get-voting-event")
class GetVotingEvent(MethodView):
    @voting_event_blp.arguments(GetVotingEventQuerySchema, location="query")
    @voting_event_blp.response(200, ApiResponse)
    @voting_event_blp.doc(
        description="Retrieves voting events based on query parameters.",
        responses={
            "200": {"description": "Voting events retrieved successfully"},
            "401": {"description": "Unauthorized access"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(False)
    def get(self, query_params):
        query_params["user_id"] = get_jwt().get("sub", {}).get("user_id")
        voting_event = VotingEventService.get_voting_event(query_params)
        return set_response(200, {"code": "success", "voting_event": voting_event})


@voting_event_blp.route("/user/get-current-tally")
class GetCurrentTally(MethodView):

    @voting_event_blp.arguments(GetVotingStatisticsQuerySchema, location="query")
    @voting_event_blp.response(200, ApiResponse)
    @voting_event_blp.doc(
        description="Retrieves the current tally of a voting event.",
        responses={
            "200": {"description": "Voting event tally retrieved successfully"},
            "401": {"description": "Unauthorized access"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(False)
    def get(self, query_params):
        get_jwt()
        event_uuid = query_params.get("uuid")
        event_type = query_params.get("event_type")
        tally_info = VotingEventService.get_current_tally(event_uuid, event_type)
        return set_response(200, {"code": "success", "tally_info": tally_info})


voting_event_blp.register_error_handler(
    VotingEventDoesNotExists, handle_voting_event_does_not_exists
)
