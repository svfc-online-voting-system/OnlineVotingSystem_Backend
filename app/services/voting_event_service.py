""" Wraps the voting event service related operations in the application. """

from hashlib import sha256
from collections import Counter
from typing import Any, Dict

from app.models.poll_options import PollOperations
from app.models.poll_votes import PollVoteOperation, StatisticsOperation
from app.services.poll_service import UserPollService
from app.utils.security.decryption import Decryption
from app.models.voting_event import UserOperations, VotingEvent, VotingEventOperations


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

    @staticmethod
    def get_current_tally(event_uuid: str, event_type: str):
        """This method gets the current tally for the voting event."""
        if event_type == "poll":
            return StatisticService.get_poll_tally(event_uuid)
        return StatisticService.get_electoral_voting_statistic(event_uuid)


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
            decryption = Decryption()
            decrypted_data = decryption.decrypt_poll_cast_entry(vote_data.get("poll_vote_token"))  # type: ignore
            voting_event_data.update(
                {"vote_data": decrypted_data, "has_user_voted": has_user_voted}
            )
            return voting_event_data
        voting_event_data.update({"has_user_voted": has_user_voted})
        return voting_event_data


class StatisticService:  # pylint: disable=R0903
    """This class contains the service for the statistics."""

    @staticmethod
    def get_electoral_voting_statistic(event_uuid: str):
        """This method gets the voting event statistics."""
        # return VotingEventOperations.get_voting_event_statistics(event_uuid)

    @staticmethod
    def get_poll_tally(event_uuid: str) -> Dict[int, Dict[str, Any]]:
        """Get statistical tally of votes per poll option with option text

        Args:
            event_uuid (str): Event UUID to get tally for

        Returns:
            Dict[int, Dict[str, Any]]: Dictionary mapping poll_option_id to vote stats
            Format: {
                option_id: {
                    'count': number_of_votes,
                    'text': option_text
                }
            }
        """
        event_uuid_bin = VotingEvent.uuid_to_bin(event_uuid)
        event_id = VotingEventOperations.get_event_id_from_uuid(event_uuid, "poll")
        event_uuid_hash = sha256(event_uuid_bin).hexdigest()

        poll_options = PollOperations.get_poll_options(event_id)  # type: ignore
        options_lookup = {opt["option_id"]: opt["option_text"] for opt in poll_options}

        decryption = Decryption()
        respondents = StatisticsOperation.get_poll_tally(event_uuid_hash)
        decrypted_votes = [
            decryption.decrypt_poll_cast_entry(r.get("poll_vote_token"))  # type: ignore
            for r in respondents
        ]

        vote_counts = Counter([vote["poll_option_id"] for vote in decrypted_votes])

        return {
            option_id: {
                "count": vote_counts.get(option_id, 0),
                "text": options_lookup.get(option_id, ""),
            }
            for option_id in options_lookup.keys()
        }
