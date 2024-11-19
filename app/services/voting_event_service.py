""" Wraps the voting event service related operations in the application. """

from app.models.voting_event import UserOperations, VotingEventOperations


class VotingEventService:  # pylint: disable=R0903
    """This class contains the service for the voting events."""

    @staticmethod
    def get_voting_events_by(voting_event_type=None, voting_status=None):
        """This method gets the voting event by the parameters."""
        return GetVotingEvents.get_voting_events_by(voting_event_type, voting_status)

    @staticmethod
    def get_voting_event(uuid: str, event_type: str):
        """This method gets the voting event by the parameters."""
        return GetVotingEvents.get_voting_event(uuid, event_type)


class GetVotingEvents:  # pylint: disable=R0903
    """This class contains the service for getting voting events."""

    @staticmethod
    def get_voting_events_by(voting_event_type=None, voting_status=None):
        """This method gets the voting events by the parameters."""
        return UserOperations.get_voting_events_by(voting_event_type, voting_status)

    @staticmethod
    def get_voting_event(uuid: str, event_type: str):
        """This method gets the voting event by the parameters."""
        return VotingEventOperations.get_voting_event_by_uuid(uuid, event_type)
