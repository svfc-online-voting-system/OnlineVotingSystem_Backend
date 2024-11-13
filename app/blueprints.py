"""This module registers all the blueprints in the application."""

from app.routes.auth import auth_blueprint
from app.routes.admin_actions import admin_action_blueprint
from app.routes.poll import poll_blueprint
from app.routes.voting_events import voting_events_blueprint
from app.routes.profile import profile


def register_blueprints(app):  # pylint: disable=C0116
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(poll_blueprint)
    app.register_blueprint(voting_events_blueprint)
    app.register_blueprint(admin_action_blueprint)
    app.register_blueprint(profile)
