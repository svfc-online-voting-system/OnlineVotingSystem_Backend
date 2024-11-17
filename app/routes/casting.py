""" Routes for casting related endpoint """

# pylint: disable=missing-function-docstring, missing-class-docstring

from logging import getLogger
from flask_smorest import Blueprint
from flask.views import MethodView
from flask_jwt_extended import jwt_required, get_jwt

from app.schemas.casting_schema import PollCastingSchema, UnCastPollCastingSchema
from app.schemas.responses import ApiResponse
from app.services.poll_service import PollService
from app.utils.response_util import set_response


casting_blp = Blueprint(
    "casting",
    __name__,
    url_prefix="/api/v1/respondent",
    description="Casting API endpoints for VoteVoyage",
)

logger = getLogger(name=__name__)


@casting_blp.route("/poll/cast")
class CastPoll(MethodView):
    @casting_blp.arguments(PollCastingSchema)
    @casting_blp.response(201, ApiResponse)
    @casting_blp.doc(
        description="Cast a vote for a poll",
        responses={
            "422": {"description": "Validation Error"},
        },
    )
    @jwt_required(optional=False)
    def post(self, data):
        """Cast a vote for a poll"""
        data["user_id"] = get_jwt().get("sub").get("user_id")  # type: ignore
        poll_service = PollService()
        poll_service.cast_poll_vote(data)
        return set_response(
            201, {"code": "success", "message": "The vote has been cast."}
        )


@casting_blp.route("/poll/uncast")
class UncastPoll(MethodView):
    @casting_blp.arguments(UnCastPollCastingSchema)
    @casting_blp.response(200, ApiResponse)
    @casting_blp.doc(
        description="Uncast a vote for a poll",
        responses={
            "422": {"description": "Validation Error"},
        },
    )
    @jwt_required(optional=False)
    def delete(self, data):
        """Uncast a vote for a poll"""
        data["user_id"] = get_jwt().get("sub").get("user_id")  # type: ignore
        poll_service = PollService()
        poll_service.uncast_poll_vote(data)
        return set_response(
            201, {"code": "success", "message": "The vote has been uncast."}
        )
