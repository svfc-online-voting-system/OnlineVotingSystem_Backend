""" SQLAlchemy model for poll_votes table. """

from sqlalchemy import VARCHAR, Column, Integer, TIMESTAMP, UniqueConstraint
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError

from app.models.base import Base
from app.utils.engine import get_session


class PollVotes(Base):  # pylint: disable=R0903
    """SQLAlchemy model for the poll_votes table."""
    
    __tablename__ = "poll_votes"
    
    poll_vote_id = Column(Integer, primary_key=True, autoincrement=True)
    poll_vote_token = Column(VARCHAR(512), nullable=False)
    voted_at = Column(TIMESTAMP, nullable=False, default="CURRENT_TIMESTAMP")
    event_uuid_hash = Column(VARCHAR(64), nullable=False, index=True)
    user_vote_hash = Column(VARCHAR(64), nullable=False, unique=True, index=True)
    
    __table_args__ = (
        UniqueConstraint("user_vote_hash", name="poll_votes_user_vote_hash_key"),
    )
    
    def to_dict(self) -> dict:
        """Converts the model instance to a dictionary."""
        return {
            "poll_vote_id": self.poll_vote_id,
            "poll_vote_token": self.poll_vote_token,
            "voted_at": self.voted_at,
            "event_uuid_hash": self.event_uuid_hash,
            "user_vote_hash": self.user_vote_hash,
        }



class PollVoteOperation:  # pylint: disable=R0903
    """Class to handle poll vote operations."""

    @staticmethod
    def add_new_poll_vote(
        poll_vote_token: str, voted_at, event_uuid_hash: str, user_vote_hash: str
    ) -> None:
        """Responsible for adding a new poll vote"""
        session = get_session()
        try:
            new_poll_vote = PollVotes(
                poll_vote_token=poll_vote_token,
                voted_at=voted_at,
                event_uuid_hash=event_uuid_hash,
                user_vote_hash=user_vote_hash,
            )
            session.add(new_poll_vote)
            session.commit()
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            session.rollback()
            raise err
        finally:
            session.close()

    @staticmethod
    def has_user_voted(user_vote_hash) -> bool:
        """Check if user has already voted without decryption, if the user voted
        query for the vote information and return it"""
        session = get_session()
        try:
            return (
                session.query(PollVotes)
                .filter(PollVotes.user_vote_hash == user_vote_hash)
                .first()
                is not None
            )
        except (OperationalError, DatabaseError) as err:
            raise err
        finally:
            session.close()

    @staticmethod
    def get_vote_count(event_id_hash: str) -> int:
        """Get total votes for an event efficiently"""
        session = get_session()
        try:
            return (
                session.query(PollVotes)
                .filter(PollVotes.event_id_hash == event_id_hash)
                .count()
            )
        except (OperationalError, DatabaseError) as err:
            raise err
        finally:
            session.close()

    @staticmethod
    def get_poll_vote_data(user_vote_hash: str):
        """Get the poll vote data"""
        session = get_session()
        try:
            poll_vote = (
                session.query(PollVotes)
                .filter(PollVotes.user_vote_hash == user_vote_hash)
                .first()
            )
            return poll_vote.to_dict() if poll_vote else None
        except (OperationalError, DatabaseError) as err:
            raise err
        finally:
            session.close()


class StatisticsOperation:  # pylint: disable=R0903
    """Class to handle statistics operations."""

    @staticmethod
    def get_poll_tally(event_uuid_hash: str) -> list[dict]:
        """Get the poll tally

        Args:
            event_uuid_hash (str): Hash of the event UUID

        Returns:
            list[dict]: List of poll vote dictionaries
        """
        session = get_session()
        try:
            respondents = (
                session.query(PollVotes)
                .filter(PollVotes.event_uuid_hash == event_uuid_hash)
                .all()
            )
            return [vote.to_dict() for vote in respondents]
        except (OperationalError, DatabaseError) as err:
            raise err
        finally:
            session.close()
