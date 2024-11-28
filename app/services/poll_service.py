""" Service routes for poll related endpoints and validation """

from hashlib import sha256
from datetime import datetime
from uuid import uuid4, UUID

from app.models.audit_log import PollRelatedLogOperations
from app.models.poll_options import PollOperations, UserPollOptionOperation
from app.models.poll_votes import PollVoteOperation
from app.models.voting_event import VotingEvent, VotingEventOperations
from app.utils.security.encryption import Encryption
from app.utils.security.hashing import HashPollVoteEntry


class PollService:
    """Wraps the poll service layer"""

    @classmethod
    def add_new_poll(cls, poll_data) -> str:
        """Responsible for adding new poll"""
        return PollVotingEventService.create_poll_voting_event(poll_data)

    @classmethod
    def delete_polls(cls, poll_ids: list[int], user_id):
        """Responsible for deleting a poll"""
        return PollVotingEventService.delete_poll_voting_events(poll_ids, user_id)

    @classmethod
    def rename_poll_title(cls, poll_id, user_id):
        """Responsible for renaming a poll title"""
        print(poll_id, user_id)

    @classmethod
    def get_poll_details(cls, user_id, poll_id):
        """Responsible for getting the poll details this is for the owner of the poll"""
        print(user_id, poll_id)

    @classmethod
    def delete_option(cls, option_id):
        """Responsible for deleting an option in a poll"""

    @classmethod
    def add_option(cls, poll_id, user_id, option_text):
        """Responsible for adding an option in a poll by their id"""

    @classmethod
    def edit_option(cls, option_id: int, new_option_text: str, user_id: int):
        """Responsible for editing an option in a poll"""

    @classmethod
    def cast_poll_vote(cls, data):
        """Responsible for casting a vote"""
        return UserPollService.cast_poll_vote(data)

    @classmethod
    def uncast_poll_vote(cls, vote_info: dict):
        """Responsible for uncasting a vote"""

    @classmethod
    def change_vote(cls, vote_info):
        """Responsible for changing a vote"""

    def get_polls(self, user_id):
        """Responsible for getting all the polls"""
        return user_id

    @classmethod
    def get_options(cls, poll_id: int):
        """Responsible for getting all the options in a poll"""
        return UserPollService.get_poll_options(poll_id)

    def has_user_voted(self, user_id, event_uuid):
        """Responsible for checking if the user has voted"""
        return UserPollService.has_user_voted(user_id, event_uuid)


class PollVotingEventService:
    """Wraps the poll voting event service layer"""

    @staticmethod
    def get_poll_voting_event(poll_id: int, user_id: int):
        """Responsible for getting the voting event"""

        return VotingEventOperations.get_voting_event(
            event_id=poll_id, event_type="poll", user_id=user_id
        )

    @staticmethod
    def delete_poll_voting_events(poll_id: list[int], user_id):
        """Responsible for deleting the voting event"""
        if not poll_id:
            raise ValueError("Poll ID cannot be empty")
        if not user_id:
            raise ValueError("User ID cannot be empty")
        VotingEventOperations.delete_voting_events(event_ids=poll_id, user_id=user_id)

    @staticmethod
    def create_poll_voting_event(poll_data: dict) -> str:
        """Responsible for creating the voting event"""
        status = "upcoming" if poll_data.get("start_date") > datetime.now() else "active"  # type: ignore
        new_poll_data_uuid = uuid4().bytes
        new_poll_data = {
            "uuid": new_poll_data_uuid,
            "created_by": poll_data.get("created_by"),
            "title": poll_data.get("title"),
            "created_at": datetime.now(),
            "last_modified_at": datetime.now(),
            "start_date": poll_data.get("start_date"),
            "end_date": poll_data.get("end_date"),
            "status": status,
            "approved": False,
            "event_type": "poll",
            "description": poll_data.get("description"),
        }
        event_id = VotingEventOperations.create_new_voting_event(
            poll_data=new_poll_data
        )
        PollRelatedLogOperations.create_poll_related_log(
            log_data={
                "uuid": uuid4().bytes,
                "user_id": poll_data.get("created_by"),
                "event_id": event_id,
                "action": "create-poll",
                "details": "Poll created",
                "timestamp": datetime.now(),
            }
        )
        return str(UUID(bytes=new_poll_data_uuid))

    @staticmethod
    def get_vote_count(event_uuid: str) -> int:
        """Responsible for getting the vote count"""
        event_uuid_bin = VotingEvent.uuid_to_bin(event_uuid)
        hashed_event_uuid = sha256(event_uuid_bin).hexdigest()
        return PollVoteOperation.get_vote_count(hashed_event_uuid)


class UserPollService:  # pylint: disable=R0903
    """Wraps the user poll service layer"""

    @staticmethod
    def get_poll_options(poll_id: int):
        """Responsible for getting the poll options"""
        return UserPollOptionOperation.get_all_poll_options(event_id=poll_id)

    @staticmethod
    def cast_poll_vote(data: dict):
        """Responsible for casting a vote encrypting data that can be linked to the user."""
        user_id = data.get("user_id")
        event_uuid_bin = VotingEvent.uuid_to_bin(data.get("event_uuid"))
        poll_option_id = data.get("poll_option_id")

        VotingEventOperations.get_voting_event_by_uuid(data.get("event_uuid"), "poll")
        is_poll_option_valid = PollOperations.is_poll_option_id_exists(
            poll_option_id  # type: ignore
        )
        if not is_poll_option_valid:
            raise ValueError("Poll option ID does not exist")

        encryption = Encryption()
        hash_poll_vote_entry = HashPollVoteEntry()

        encrypted_data = encryption.encrypt_poll_cast_entry(
            user_id, event_uuid_bin, poll_option_id
        )
        event_uuid_hash, user_vote_hash = hash_poll_vote_entry.create_poll_vote_hashes(
            user_id, event_uuid_bin  # type: ignore
        )
        PollVoteOperation.add_new_poll_vote(
            encrypted_data, datetime.now(), event_uuid_hash, user_vote_hash
        )

    @staticmethod
    def has_user_voted(user_id: int, event_uuid: str) -> bool:
        """Responsible for checking if the user has voted"""
        user_vote_hash = sha256(
            f"{user_id}-{VotingEvent.uuid_to_bin(event_uuid).hex()}".encode()
        ).hexdigest()
        return PollVoteOperation.has_user_voted(user_vote_hash)
