""" This is the routes for admin actions. """
from logging import getLogger
from os import getenv

from flask import Blueprint, request
from flask_jwt_extended import jwt_required

from app.services.admin import Admin
from app.utils.response_utils import set_response

logger = getLogger(name=__name__)
admin_action = Blueprint('admin_action', __name__)
ENVIRONMENT = getenv('ENVIRONMENT', 'development')
is_production = ENVIRONMENT == 'production'


@jwt_required(locations=['cookies', 'headers'])
@admin_action.route(rule='/admin/approve-vote', methods=['POST'])
def approve_vote():
    """ This route is used to approve a vote. """
    admin = Admin()
    if request.json is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    admin.approve_vote(dict(request.json))
    return set_response(200, {
        'code': 'success',
        'message': 'The vote has been successfully approve!'
    })
