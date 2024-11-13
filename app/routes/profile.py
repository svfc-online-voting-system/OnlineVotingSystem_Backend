""" Wraps the profile related routes. """

from flask import Blueprint, request
from flask_jwt_extended import get_jwt, jwt_required

from app.schemas.profile_schema import ProfileSchema
from app.services.profile_services import ProfileService
from app.utils.response_util import set_response

profile = Blueprint("profile", __name__)


@profile.route("/v1/user/get-my-profile-settings", methods=["GET"])
@jwt_required(optional=False)
def get_my_profile_settings():
    """Retrieves the profile of the user."""
    user_id = get_jwt().get("sub").get("user_id")  # type: ignore
    profile_data = ProfileService.get_my_profile_settings(user_id)
    return set_response(200, {"code": "success", "profile_data": profile_data})


@profile.route("/v1/user/settings", methods=["GET"])
@jwt_required(optional=False)
def get_settings():
    """Retrieves the settings of the user."""
    get_jwt()
    return set_response(
        200, {"code": "success", "message": "Settings retrieved successfully."}
    )


@profile.route("/v1/user/update-profile", methods=["POST"])
@jwt_required(optional=False)
def update_profile():
    """Updates the profile of the user."""
    get_jwt()
    data = request.json
    profile_schema = ProfileSchema()
    validated_data = profile_schema.load(data)  # type: ignore pylint: disable=unused-variable
    return set_response(
        200, {"code": "success", "message": "Profile updated successfully."}
    )
