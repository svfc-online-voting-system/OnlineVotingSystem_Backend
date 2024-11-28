""" Wraps the profile related routes. """

# pylint: disable=missing-function-docstring, missing-class-docstring

from logging import getLogger

from flask.views import MethodView
from flask_smorest import Blueprint
from flask_jwt_extended import get_jwt, jwt_required

from app.schemas.profile_schema import ProfileSchema
from app.schemas.responses import ApiResponse
from app.services.profile_services import ProfileService
from app.utils.response_util import set_response

logger = getLogger(__name__)

profile_blp = Blueprint(
    "profile",
    __name__,
    url_prefix="/api/v1/profile",
    description="Profile API endpoints for VoteVoyage",
)


@profile_blp.route("/my-profile")
class MyProfile(MethodView):
    @profile_blp.response(200, ApiResponse)
    @profile_blp.doc(
        description="Retrieve user profile settings",
        responses={
            "200": {"description": "Profile retrieved successfully"},
            "401": {"description": "Unauthorized access"},
            "404": {"description": "Profile not found"},
        },
    )
    @jwt_required(False)
    def get(self):
        user_id = get_jwt().get("sub", {}).get("user_id")
        profile_data = ProfileService.get_my_profile_settings(user_id)
        return set_response(200, {"code": "success", "profile_data": profile_data})


@profile_blp.route("/update-profile")
class UpdateProfile(MethodView):
    @profile_blp.arguments(ProfileSchema)
    @profile_blp.response(200, ApiResponse)
    @profile_blp.doc(
        description="Update user profile",
        responses={
            "200": {"description": "Profile updated successfully"},
            "401": {"description": "Unauthorized access"},
            "422": {"description": "Validation error"},
        },
    )
    @jwt_required(False)
    def patch(self, profile_data):
        profile_data["user_id"] = get_jwt().get("sub", {}).get("user_id")
        ProfileService.update_profile(profile_data)
        return set_response(
            200, {"code": "success", "message": "Profile updated successfully"}
        )
