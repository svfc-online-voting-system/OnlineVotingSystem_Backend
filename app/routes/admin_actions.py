""" This is the routes for admin actions. """

from logging import getLogger
from os import getenv

from flask import Blueprint, request
from flask_jwt_extended import get_jwt, jwt_required

from app.services.admin_service import AdminService
from app.utils.response_util import set_response

logger = getLogger(name=__name__)
admin_action_blueprint = Blueprint("admin_action", __name__)
ENVIRONMENT = getenv("ENVIRONMENT", "development")
is_production = ENVIRONMENT == "production"


@admin_action_blueprint.route("/v1/admin/approve-voting-event", methods=["POST"])
@jwt_required(optional=False)
def approve_vote():
    """This route is used to approve a vote."""
    is_admin = get_jwt().get("sub").get("role") == "admin"  # type: ignore
    if not is_admin:
        return set_response(401, "Unauthorized")
    if request.json is None:
        return set_response(
            400,
            {"code": "invalid_request", "message": "Bad Request: No data provided."},
        )
    AdminService.approve_voting_event(dict(request.json))
    return set_response(
        200, {"code": "success", "message": "The vote has been successfully approve!"}
    )


@admin_action_blueprint.route("/v1/admin/reject-voting-event", methods=["POST"])
@jwt_required(optional=False)
def reject_vote():
    """This route is used to reject a vote."""


@admin_action_blueprint.route("/v1/admin/get-all-voting-events", methods=["GET"])
@jwt_required(optional=False)
def get_all_voting_events():
    """This route is used to get all voting events."""
    voting_event_type = request.args.get("voting_event_type")
    voting_events = AdminService.get_all_voting_events_by(voting_event_type)
    return set_response(200, {"code": "success", "voting_events": voting_events})
