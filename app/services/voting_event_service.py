""" Wraps the voting event service related operations in the application. """

from hashlib import sha256

from app.utils.security.decryption import Decryption

from app.models.poll_votes import PollVoteOperation
from app.models.voting_event import UserOperations, VotingEvent, VotingEventOperations
from app.services.poll_service import UserPollService


class VotingEventService:  # pylint: disable=R0903
    """This class contains the service for the voting events."""

    @staticmethod
    def get_voting_events_by(voting_event_type=None, voting_status=None):
        """This method gets the voting event by the parameters."""
        return GetVotingEvents.get_voting_events_by(voting_event_type, voting_status)

    @staticmethod
    def get_voting_event(query_params: dict):
        """This method gets the voting event by the parameters."""
        return GetVotingEvents.get_voting_event(query_params)


class GetVotingEvents:  # pylint: disable=R0903
    """This class contains the service for getting voting events."""

    @staticmethod
    def get_voting_events_by(voting_event_type=None, voting_status=None):
        """This method gets the voting events by the parameters."""
        return UserOperations.get_voting_events_by(voting_event_type, voting_status)

    @staticmethod
    def get_voting_event(query_params: dict):
        """This method gets the voting event by the parameters."""
        event_uuid = query_params.get("uuid")
        user_id = query_params.get("user_id")
        has_user_voted = UserPollService.has_user_voted(
            user_id, event_uuid  # type: ignore
        )
        voting_event_data = VotingEventOperations.get_voting_event_by_uuid(
            query_params.get("uuid"), query_params.get("event_type")  # type: ignore
        )
        if has_user_voted:
            user_vote_hash = sha256(
                f"{user_id}-{VotingEvent.uuid_to_bin(event_uuid).hex()}".encode()
            ).hexdigest()
            vote_data = PollVoteOperation.get_poll_vote_data(user_vote_hash)  # type: ignore
            print(vote_data)
            decryption = Decryption()
            decrypted_data = decryption.decrypt_poll_cast_entry(vote_data.get("poll_vote_token"))  # type: ignore
            print(decrypted_data)
            voting_event_data.update(
                {"vote_data": decrypted_data, "has_user_voted": has_user_voted}
            )
            return voting_event_data
        voting_event_data.update({"has_user_voted": has_user_voted})
        return voting_event_data
