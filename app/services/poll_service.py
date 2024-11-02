""" Service routes for poll related endpoints and validation """
from datetime import datetime
from uuid import uuid4, UUID

from app.models.audit_log import PollRelatedLogOperations
from app.models.voting_event import VotingEventOperations


class PollService:
    """ Wraps the poll service layer """
    @classmethod
    def add_new_poll(cls, poll_data) -> str:
        """ Responsible for adding new poll """
        return PollVotingEventService.create_poll_voting_event(poll_data)

    @classmethod
    def delete_poll(cls, poll_id, user_id):
        """ Responsible for deleting a poll """
        return PollVotingEventService.delete_poll_voting_event(poll_id, user_id)

    @classmethod
    def rename_poll_title(cls, poll_id, user_id):
        """ Responsible for renaming a poll title """
        print(poll_id, user_id)

    @classmethod
    def get_poll_details(cls):
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
    def change_vote(cls, vote_info):
        """ Responsible for changing a vote """


class PollVotingEventService:
    """ Wraps the poll voting event service layer """
    @staticmethod
    def get_poll_voting_event(poll_id: int):
        """ Responsible for getting the voting event """
        if not poll_id:
            raise ValueError("Poll ID cannot be empty")

        return VotingEventOperations.get_voting_event(event_id=poll_id, event_type='poll')

    @staticmethod
    def delete_poll_voting_event(poll_id, user_id):
        """ Responsible for deleting the voting event """
        if not poll_id:
            raise ValueError("Poll ID cannot be empty")
        if not user_id:
            raise ValueError("User ID cannot be empty")
        VotingEventOperations.delete_voting_event(event_id=poll_id, user_id=user_id)

    @staticmethod
    def create_poll_voting_event(poll_data: dict) -> str:
        """ Responsible for creating the voting event """
        status = "upcoming" if poll_data.get('start_date') > datetime.now() else "active" # type: ignore
        new_poll_data_uuid = uuid4().bytes
        new_poll_data = {
            'uuid': new_poll_data_uuid,
            'created_by': poll_data.get('created_by'),
            'title': poll_data.get('title'),
            'created_at': datetime.now(),
            'last_modified_at': datetime.now(),
            'start_date': poll_data.get('start_date'),
            'end_date': poll_data.get('end_date'),
            'status': status,
            'approved': False,
            'event_type': 'poll',
            'description': poll_data.get('description')
        }
        event_id = VotingEventOperations.create_new_voting_event(poll_data=new_poll_data)
        PollRelatedLogOperations.create_poll_related_log(log_data={
            'uuid': uuid4().bytes,
            'user_id': poll_data.get('created_by'),
            'event_id': event_id,
            'action': 'create-poll',
            'details': 'Poll created',
            'timestamp': datetime.now()
        })
        return str(UUID(bytes=new_poll_data_uuid))
