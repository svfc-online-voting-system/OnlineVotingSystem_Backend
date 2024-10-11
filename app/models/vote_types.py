""" This is the model for vote types that will represent the vote_types table """

from app.utils.engine import get_session
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy import Column, Integer, String, select, update, Enum
from sqlalchemy.orm import relationship
from app.models.base import Base


class VoteTypes(Base):
    """ Class representing vote_types table. """
    __tablename__ = 'vote_types'
    vote_type_id = Column(Integer, primary_key=True, autoincrement=True)
    type_name = Column(Enum('poll', 'electoral'), nullable=False)
    title = Column(String(255), nullable=False)
    vote_types = relationship('Votes', back_populates='vote_types', uselist=True, cascade='all, delete-orphan')
    ballots = relationship('Ballots', back_populates='vote_types', uselist=True, cascade='all, delete-orphan')
    
    @classmethod
    def add_new_vote(cls, poll_title: str, poll_type: str) -> int:
        """ Responsible for adding new vote type returning the id for referencing in the caller """
        session = get_session()
        try:
            if poll_type not in ['poll', 'electoral']:
                raise ValueError
            new_vote = cls(
                type_name=poll_type,
                title=poll_title
            )
            session.add(new_vote)
            session.commit()
            return new_vote.vote_type_id
        except ValueError as ve:
            raise ve
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err