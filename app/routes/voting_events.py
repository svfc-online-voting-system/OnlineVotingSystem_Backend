""" Wraps all the route that is related to a broad retrieval of voting events """

from logging import getLogger

from flask import Blueprint, request
from flask_jwt_extended import get_jwt, jwt_required

from app.services.voting_event_service import VotingEventService
from app.schemas.voting_event_query import VotingEventQuerySchema
from app.utils.response_util import set_response

voting_events_blueprint = Blueprint("voting_events", __name__)

logger = getLogger(name=__name__)


@voting_events_blueprint.route("/v1/user/get-voting-event-by", methods=["GET"])
@jwt_required(optional=False)
def get_voting_event_by():
    """Retrieves voting events based on query parameters."""
    get_jwt()
    schema = VotingEventQuerySchema()
    query_params = schema.load(request.args)
    voting_event_type = query_params.get("voting_event_type")  # type: ignore
    voting_status = query_params.get("voting_status")  # type: ignore

    voting_events = VotingEventService.get_voting_events_by(
        voting_event_type, voting_status
    )

    return set_response(200, {"code": "success", "data": voting_events})
