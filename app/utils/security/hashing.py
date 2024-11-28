""" Security utilities for hashing poll vote entries. """

from hashlib import sha256


class HashPollVoteEntry:  # pylint: disable=R0903
    """Security utilities for hashing poll vote entries."""

    def create_poll_vote_hashes(self, user_id: int, event_uuid: bytes):
        """Hash the poll vote entry."""
        event_uuid_hash = sha256(event_uuid).hexdigest()
        user_vote_hash = sha256(f"{user_id}-{event_uuid.hex()}".encode()).hexdigest()
        return event_uuid_hash, user_vote_hash
