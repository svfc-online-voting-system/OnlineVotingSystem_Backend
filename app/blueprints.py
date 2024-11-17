"""This module registers all the blueprints in the application."""

from flask_smorest import Api

from app.routes.admin_actions import admin_action_blp
from app.routes.auth import auth_blp
from app.routes.casting import casting_blp
from app.routes.poll import poll_blp
from app.routes.profile import profile_blp
from app.routes.voting_events import voting_event_blp


def register_blueprints(api: Api):  # pylint: disable=C0116
    api.register_blueprint(auth_blp)
    api.register_blueprint(admin_action_blp)
    api.register_blueprint(casting_blp)
    api.register_blueprint(poll_blp)
    api.register_blueprint(profile_blp)
    api.register_blueprint(voting_event_blp)
