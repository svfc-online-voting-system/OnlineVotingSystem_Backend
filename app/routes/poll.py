""" Routes for poll related endpoint """

from logging import getLogger
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask import Blueprint, request

from app.utils.error_handlers import handle_general_exception, handle_value_error
from app.utils.response_utils import set_response
from app.services.poll_service import PollService

logger = getLogger(name=__name__)
poll_blueprint = Blueprint('poll', __name__)

poll_blueprint.register_error_handler(Exception, handle_general_exception)
poll_blueprint.register_error_handler(ValueError, handle_value_error)


@jwt_required(locations=['cookies', 'headers'])
@poll_blueprint.route(rule='/user/add-poll', methods=['POST'])
def add_poll():
    """ Add a new poll for the user """
    if request.json is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    poll_title = str(request.json.get('vote_type'))
    user_identity = get_jwt_identity()
    user_id = user_identity['user_id']
    if str(request.json.get('vote_type')).lower() != 'poll' or poll_title is None:
        raise ValueError('Invalid data format')
    poll_service = PollService()
    poll_service.add_new_poll(poll_title=poll_title, user_id=user_id)
    return set_response(201, {
        'code': 'success',
        'message': 'The poll has been created.'})


@poll_blueprint.route(rule='/user/delete-poll', methods=['DELETE'])
@jwt_required(locations=['cookies', 'headers'])
def delete_poll():
    """ This route is used to delete a poll. """
    if request.json is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    poll_id = request.json.get('poll_id')
    poll_service = PollService()
    poll_service.delete_poll(poll_id=poll_id)


@poll_blueprint.route(rule='/user/rename-poll', methods=['PATCH'])
@jwt_required(locations=['cookies', 'headers'])
def rename_poll():
    """ This route is used to rename a poll. """
    if request.json is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    poll_id = request.json.get('poll_id')
    poll_service = PollService()
    poll_service.rename_poll_title(poll_id=poll_id)


@poll_blueprint.route(rule='/user/get_poll_details', methods=['GET'])
@jwt_required(locations=['cookies', 'headers'])
def get_poll_details():
    """ This route is used to get the details of a poll. """
    if request.json is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    poll_id = request.json.get('poll_id')
    poll_service = PollService()
    poll_service.get_poll_details(poll_id=poll_id)


@poll_blueprint.route(rule='/user/add-option', methods=['POST'])
@jwt_required(locations=['cookies', 'headers'])
def add_option():
    """ This route is used to add a new option to a poll. """
    if request.json is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    poll_id = request.json.get('poll_id')
    poll_service = PollService()
    poll_service.get_poll_details(poll_id=poll_id)


@poll_blueprint.route(rule='/user/edit-option', methods=['PATCH'])
@jwt_required(locations=['cookies', 'headers'])
def edit_option():
    """ This route is used to edit a poll option. """
    if request.json is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    poll_id = request.json.get('poll_id')
    poll_service = PollService()
    poll_service.get_poll_details(poll_id=poll_id)


@poll_blueprint.route(rule='/user/cast-poll-vote', methods=['POST'])
@jwt_required(locations=['cookies', 'headers'])
def cast_poll_vote():
    """ This route is used to cast a vote. """
    if request.json is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    vote_info = request.json
    poll_service = PollService()
    poll_service.cast_poll_vote(vote_info=vote_info)


@poll_blueprint.route(rule='/user/uncast-poll-vote', methods=['POST'])
@jwt_required(locations=['cookies', 'headers'])
def uncast_poll_vote():
    """ This route is used to uncast a vote. """
    if request.json is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    vote_info = request.json
    poll_service = PollService()
    poll_service.uncast_poll_vote(vote_info=vote_info)


@poll_blueprint.route(rule='/user/change-vote', methods=['PATCH'])
@jwt_required(locations=['cookies', 'headers'])
def change_vote():
    """ This route is used to change a vote. """
    if request.json is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    vote_info = request.json
    poll_service = PollService()
    poll_service.change_vote(vote_info=vote_info)
