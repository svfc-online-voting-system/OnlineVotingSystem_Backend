""" SQLAlchemy model for poll_votes table. """

from sqlalchemy import DATETIME, VARCHAR, Column, Integer
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError

from app.models.base import Base
from app.utils.engine import get_session


class PollVotes(Base):  # pylint: disable=R0903
    """SQLAlchemy model for poll_votes table."""

    __tablename__ = "poll_votes"

    poll_vote_id = Column(Integer, primary_key=True, autoincrement=True)
    poll_vote_token = Column(VARCHAR(512), nullable=False)
    voted_at = Column(DATETIME, nullable=False)


class PollVoteOperation:  # pylint: disable=R0903
    """Class to handle poll vote operations."""

    @staticmethod
    def add_new_poll_vote(poll_vote_token: str, voted_at) -> None:
        """Responsible for adding a new poll vote"""
        session = get_session()
        try:
            new_poll_vote = PollVotes(
                poll_vote_token=poll_vote_token, voted_at=voted_at
            )
            session.add(new_poll_vote)
            session.commit()
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            session.rollback()
            raise err
        finally:
            session.close()
