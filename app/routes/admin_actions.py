""" This is the routes for admin actions. """

# pylint: disable=missing-function-docstring, missing-class-docstring

from logging import getLogger
from functools import wraps

from flask.views import MethodView
from flask_smorest import Blueprint
from flask_jwt_extended import get_jwt, jwt_required

from app.schemas.admin_action_schema import (
    ApproveVotingEventSchema,
    VotingEventQuerySchema,
)
from app.schemas.responses import ApiResponse
from app.services.admin_service import AdminService
from app.utils.response_util import set_response

logger = getLogger(name=__name__)

admin_action_blp = Blueprint(
    "admin_action",
    __name__,
    url_prefix="/api/v1/admin",
    description="Admin API endpoints for VoteVoyage",
)


def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            is_admin = get_jwt().get("role") == "admin"
            if not is_admin:
                return set_response(
                    401, {"code": "unauthorized", "message": "Admin access required"}
                )
            return fn(*args, **kwargs)

        return decorator

    return wrapper


@admin_action_blp.route("/approve-voting-event")
class ApproveVotingEvent(MethodView):
    @admin_action_blp.arguments(ApproveVotingEventSchema)
    @admin_action_blp.response(200, ApiResponse)
    @admin_action_blp.doc(
        description="Approve a voting event",
        responses={
            "200": {"description": "Voting event approved successfully"},
            "401": {"description": "Unauthorized access"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(False)
    @admin_required()
    def post(self, approve_data):
        admin_id = get_jwt().get("sub", {}).get("user_id")
        approve_data["admin_id"] = admin_id
        AdminService.approve_voting_event(approve_data)
        return set_response(
            200,
            {"code": "success", "message": "Voting event approved successfully"},
        )


@admin_action_blp.route("/get-all-voting-events")
class GetAllVotingEvents(MethodView):
    @admin_action_blp.arguments(VotingEventQuerySchema, location="query")
    @admin_action_blp.response(200, ApiResponse)
    @admin_action_blp.doc(
        description="Get all voting events",
        responses={
            "200": {"description": "Voting events retrieved successfully"},
            "401": {"description": "Unauthorized access"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(False)
    @admin_required()
    def get(self, query_params):
        voting_events = AdminService.get_all_voting_events_by(
            query_params.get("voting_event_type")
        )
        return set_response(200, {"code": "success", "voting_events": voting_events})
