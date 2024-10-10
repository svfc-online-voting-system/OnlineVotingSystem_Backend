""" Service routes for poll related endpoints and validation """

from app.models.votes import Votes
from app.models.vote_types import VoteTypes
from app.models.poll_options import PollOptions


class PollService:
    """ Class poll service layer related to poll actions """
    @classmethod
    def add_new_poll(cls, poll_title: str, user_id) -> int:
        """ Responsible for adding new poll """
        if len(poll_title) > 255:
            raise ValueError
        votes = Votes()
        vote_types = VoteTypes()
        vote_type_id = vote_types.add_new_vote(poll_title=poll_title.strip(), poll_type='poll')
        return votes.add_new_votes(user_id, vote_type_id)
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