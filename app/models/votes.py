""" Represent the shape of the votes table in the database """
from datetime import datetime

from sqlalchemy.orm import relationship
from sqlalchemy.sql import expression
from sqlalchemy.sql.operators import and_

from app.exception.votes_exception import VoteDoesNotExists
from app.utils.engine import get_session
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy import Column, Integer, select, update, Boolean, ForeignKey, DateTime, delete
from app.models.base import Base


class Votes(Base):
    """ Class representing the form of the votes table """
    __tablename__ = 'votes'
    vote_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    vote_type_id = Column(Integer, ForeignKey('vote_types.vote_type_id'))
    vote_timestamp = Column(DateTime, nullable=False, default=datetime.now())
    approved = Column(Boolean, nullable=False, default=expression.false())
    vote_types = relationship('VoteTypes',
                              back_populates='vote_types',
                              uselist=False, cascade='all, delete-orphan')
    users = relationship('Users',
                         back_populates='users',
                         uselist=False, cascade="all, delete-orphan")
    
    @classmethod
    def add_new_votes(cls, user_id: int, vote_type_id: int) -> int:
        """ Responsible for adding new votes associated id and returning the id for referencing in the caller """
        session = get_session()
        try:
            new_votes = cls(
                user_id = user_id,
                vote_type_id = vote_type_id,
                vote_timestamp = datetime.now(),
                approved = False
            )
            session.add(new_votes)
            session.commit()
            return new_votes.vote_id
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err
    
    
    @classmethod
    def delete_vote(cls, info: dict) -> bool:
        """ Responsible for deleting a vote. """
        session = get_session()
        try:
            delete_statement = (
                delete(cls)
                .where(cls.vote_id == info.get('vote_id'))
                .where(cls.user_id == info.get('user_id'))
                .returning()
            )
            result = session.execute(delete_statement).first()
            session.commit()
            if result is None:
                raise VoteDoesNotExists
            return True
        except VoteDoesNotExists as vdne:
            raise vdne
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err
    
    @classmethod
    def approve_vote(cls, vote_metadata: dict) -> bool:
        """ Function for flipping the approval status of the vote """
        session = get_session()
        try:
            approve_vote_statement = (
                update(cls)
                .where(
                    and_(
                        cls.vote_id == vote_metadata.get('vote_id'),
                        cls.user_id == vote_metadata.get('user_id')
                    )
                )
                .values(approved=True)
                .returning(cls.vote_id)
            )
            result = session.execute(approve_vote_statement).first()
            session.commit()
            if result is None:
                raise VoteDoesNotExists("Vote does not exist.")
            return True
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err
    
    @classmethod
    def get_vote_info(cls, vote_data):
        session = get_session()
        try:
            get_vote_info = (
                select(cls)
                .where(
                    and_(
                        cls.vote_id == vote_data.get('vote_id'),
                        cls.user_id == vote_data.get('user_id')
                    )
                )
            )
            vote_info = session.execute(get_vote_info).first()
            if vote_info is None:
                raise VoteDoesNotExists
            return vote_info
        except VoteDoesNotExists as vdne:
            raise vdne
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err