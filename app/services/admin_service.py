""" These are the services that the admin are able to access. """

from app.models.voting_event import AdminOperations


class AdminService:  # pylint: disable=R0903
    """Class that will contain all the action the admin user can do."""

    @classmethod
    def approve_voting_event(cls, vote_metadata: dict):
        """Service that will call and validate the approval of the vote"""
        print(vote_metadata.get("voting_event_id"))
        print(vote_metadata.get("admin_id"))

    @classmethod
    def reject_voting_event(cls, vote_metadata: dict):
        """Service that will call and validate the rejection of the vote"""

    @classmethod
    def get_all_voting_events_by(cls, voting_event_type=None):
        """Service that will call and validate the getting of all voting events"""
        return GetVotingEvents.get_voting_events_by(voting_event_type)


class GetVotingEvents:  # pylint: disable=R0903
    """Class that will contain the logic to get all voting events."""

    @classmethod
    def get_voting_events_by(cls, voting_event_type=None):
        """Service that will call and validate the getting of all voting events"""
        return AdminOperations.get_all_voting_events_by(voting_event_type)
