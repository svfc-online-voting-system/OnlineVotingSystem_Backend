""" Service routes for poll related endpoints and validation """
from datetime import datetime
from uuid import uuid4

from app.models.voting_event import VotingEventOperations


class PollService:
    """ Class poll service layer related to poll actions """
    @classmethod
    def add_new_poll(cls, poll_data: dict) -> int:
        """ Responsible for adding new poll """
        if poll_data is None:
            raise ValueError("Poll data cannot be empty")
        voting_event_uuid = uuid4().bytes
        new_poll_data = {
            'uuid': voting_event_uuid,
            'created_by': poll_data.get('user_id'),
            'title': poll_data.get('title'),
            'created_at': datetime.now(),
            'last_modified_at': poll_data.get('last_modified_at'),
            'start_date': poll_data.get('start_date'),
            'end_date': poll_data.get('end_date'),
            'status': poll_data.get('status'),
            'approved': False,
            'event_type': 'poll',
            'description': poll_data.get('description')
        }
        return VotingEventOperations.create_new_voting_event(poll_data=new_poll_data)
    @classmethod
    def delete_poll(cls, poll_id, user_id):
        """ Responsible for deleting a poll """
        print(poll_id, user_id)
    
    @classmethod
    def rename_poll_title(cls, poll_id, user_id):
        """ Responsible for renaming a poll title """
        print(poll_id, user_id)
    
    @classmethod
    def get_poll_details(cls, poll_id):
        """ Responsible for getting the poll details """
        return 'Poll details'
    
    @classmethod
    def delete_option(cls, option_id):
        """ Responsible for deleting an option in a poll """
    
    @classmethod
    def add_option(cls, poll_id, user_id, option_text):
        """ Responsible for adding an option in a poll by their id """
    
    @classmethod
    def edit_option(cls, option_id: int, new_option_text: str):
        """ Responsible for editing an option in a poll """
    
    @classmethod
    def cast_poll_vote(cls, event_id, option_id, user_id):
        """ Responsible for casting a vote """
    
    @classmethod
    def uncast_poll_vote(cls, vote_info: dict):
        """ Responsible for uncasting a vote """
    
    @classmethod
    def change_vote(cls, vote_info: dict):
        """ Responsible for changing a vote """
