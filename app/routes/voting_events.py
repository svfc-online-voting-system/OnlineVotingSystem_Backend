""" Wraps all the route that is related to a broad retrieval of voting events """

# pylint: disable=missing-function-docstring, missing-class-docstring

from logging import getLogger

from flask.views import MethodView
from flask_smorest import Blueprint
from flask_jwt_extended import get_jwt, jwt_required

from app.schemas.responses import ApiResponse
from app.services.voting_event_service import VotingEventService
from app.schemas.voting_event_query import VotingEventQuerySchema
from app.utils.response_util import set_response

voting_event_blp = Blueprint(
    "voting_events", __name__, url_prefix="/api/v1/voting-events"
)

logger = getLogger(name=__name__)


@voting_event_blp.route("/v1/user/get-voting-event-by")
class GetVotingEventBy(MethodView):
    """Retrieves voting events based on query parameters."""

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
