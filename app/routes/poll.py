""" Routes for poll related endpoint """

from logging import getLogger

from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.services.poll_service import PollService
from app.utils.error_handlers import handle_general_exception, handle_value_error
from app.utils.response_utils import set_response

logger = getLogger(name=__name__)
poll_blueprint = Blueprint('poll', __name__)

poll_blueprint.register_error_handler(Exception, handle_general_exception)
poll_blueprint.register_error_handler(ValueError, handle_value_error)


@jwt_required(locations=['cookies', 'headers'])
@poll_blueprint.route(rule='/user/add-poll', methods=['POST'])
def add_poll():
    """ Add a new poll for the user """
    data = request.json
    if data is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    poll_title = str(data.get('vote_type'))
    poll_data = data
    user_identity = get_jwt_identity()
    print(user_identity)
    if str(request.json.get('vote_type')).lower() != 'poll' or poll_title is None:
        raise ValueError('Invalid data format')
    poll_service = PollService()
    poll_service.add_new_poll(poll_data=poll_data)
    return set_response(201, {
        'code': 'success',
        'message': 'The poll has been created.'})


@poll_blueprint.route(rule='/user/delete-poll', methods=['DELETE'])
@jwt_required(locations=['cookies', 'headers'])
def delete_poll():
    """ This route is used to delete a poll. """
    data = request.json
    if data is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    poll_id = data.get('poll_id')
    poll_service = PollService()
    poll_service.delete_poll(poll_id=poll_id, user_id=get_jwt_identity())
    return set_response(200, {
        'code': 'success',
        'message': 'The poll has been deleted.'})


@poll_blueprint.route(rule='/user/rename-poll', methods=['PATCH'])
@jwt_required(locations=['cookies', 'headers'])
def rename_poll():
    """ This route is used to rename a poll. """
    data = request.json
    if data is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    poll_id = data.get('poll_id')
    poll_service = PollService()
    poll_service.rename_poll_title(poll_id=poll_id, user_id=get_jwt_identity())
    return set_response(200, {
        'code': 'success',
        'message': 'The poll has been renamed.'})


@poll_blueprint.route(rule='/user/get_poll_details', methods=['GET'])
@jwt_required(locations=['cookies', 'headers'])
def get_poll_details():
    """ This route is used to get the details of a poll. """
    data = request.json
    if data is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    poll_service = PollService()
    details = poll_service.get_poll_details()
    return set_response(200, {
        'code': 'success',
        'message': 'Poll details retrieved successfully.',
        'data': details})
    


@poll_blueprint.route(rule='/user/add-option', methods=['POST'])
@jwt_required(locations=['cookies', 'headers'])
def add_option():
    """ This route is used to add a new option to a poll. """
    data = request.json
    if data is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    poll_id = data.get('poll_id')
    option_text = data.get('option_text')
    poll_service = PollService()
    poll_service.add_option(poll_id=poll_id, user_id=get_jwt_identity(), option_text=option_text)
    return set_response(201, {
        'code': 'success',
        'message': 'The option has been added.'})


@poll_blueprint.route(rule='/user/edit-option', methods=['PATCH'])
@jwt_required(locations=['cookies', 'headers'])
def edit_option():
    """ This route is used to edit a poll option. """
    data = request.json
    if data is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    option_id = data.get('option_id')
    new_option_text = data.get('new_option_text')
    poll_service = PollService()
    poll_service.edit_option(option_id, new_option_text)
    return set_response(200, {
        'code': 'success',
        'message': 'The option has been edited.'})


@poll_blueprint.route(rule='/user/cast-poll-vote', methods=['POST'])
@jwt_required(locations=['cookies', 'headers'])
def cast_poll_vote():
    """ This route is used to cast a vote. """
    data = request.json
    if data is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    event_id = data.get('event_id')
    option_id = data.get('option_id')
    poll_service = PollService()
    poll_service.cast_poll_vote(event_id=event_id, option_id=option_id, user_id=get_jwt_identity())
    return set_response(201, {
        'code': 'success',
        'message': 'The vote has been cast.'})


@poll_blueprint.route(rule='/user/uncast-poll-vote', methods=['POST'])
@jwt_required(locations=['cookies', 'headers'])
def uncast_poll_vote():
    """ This route is used to uncast a vote. """
    data = request.json
    if data is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    vote_info = data
    poll_service = PollService()
    poll_service.uncast_poll_vote(vote_info=vote_info)
    return set_response(201, {
        'code': 'success',
        'message': 'The vote has been uncast.'})


@poll_blueprint.route(rule='/user/change-vote', methods=['PATCH'])
@jwt_required(locations=['cookies', 'headers'])
def change_vote():
    """ This route is used to change a vote. """
    data = request.json
    if data is None:
        return set_response(400, {
            'code': 'invalid_request',
            'message': 'Bad Request: No data provided.'})
    vote_info = request.json
    poll_service = PollService()
    poll_service.change_vote(vote_info=vote_info)
    return set_response(200, {
        'code': 'success',
        'message': 'The vote has been changed.'})
