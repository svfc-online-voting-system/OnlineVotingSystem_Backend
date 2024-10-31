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
    def delete_poll(cls, poll_id):
        """ Responsible for deleting a poll """
        pass
    
    @classmethod
    def rename_poll_title(cls, poll_id):
        """ Responsible for renaming a poll title """
        pass
    
    @classmethod
    def get_poll_details(cls, poll_id):
        """ Responsible for getting the poll details """
        pass
    
    @classmethod
    def delete_option(cls, option_id: int):
        """ Responsible for deleting an option in a poll """
        pass
    
    @classmethod
    def add_option(cls, poll_id: int):
        """ Responsible for adding an option in a poll by their id """
        pass
    
    @classmethod
    def edit_option(cls, option_id: int):
        """ Responsible for editing an option in a poll """
        pass
    
    @classmethod
    def cast_poll_vote(cls, vote_info: dict):
        """ Responsible for casting a vote """
        pass
    
    @classmethod
    def uncast_poll_vote(cls, vote_info: dict):
        """ Responsible for uncasting a vote """
        pass
    
    @classmethod
    def change_vote(cls, vote_info: dict):
        """ Responsible for changing a vote """
        pass