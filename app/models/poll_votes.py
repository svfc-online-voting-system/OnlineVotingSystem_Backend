""" This is the model representing the poll_votes table """
from app.utils.engine import get_session
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy import Column, Integer, relationship, ForeignKey, insert, delete, and_, update
from app.models.base import Base

class PollVotes(Base):
    __tablename__ = 'poll_votes'
    poll_vote_id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    vote_id = Column(Integer, ForeignKey('votes.vote_id'), nullable=False)
    option_id = Column(Integer, ForeignKey('poll_options.option_id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    user = relationship('Users', back_populates='poll_votes', uselist=False, cascade='all, delete-orphan')
    votes = relationship('Votes', back_populates='poll_votes', uselist=False, cascade='all, delete-orphan')
    poll_options = relationship('PollOptions', back_populates='poll_votes', uselist=False, cascade='all, delete-orphan')
    
    @classmethod
    def cast_poll_vote(cls, vote_info: dict) -> bool:
        """ Responsible for casting a vote """
        session = get_session()
        try:
            new_poll_vote_stmnt = (
                insert(cls).values(vote_info)
            )
            session.execute(new_poll_vote_stmnt)
            session.commit()
            return True
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err
        
    @classmethod
    def uncast_poll_vote(cls, vote_info: dict) -> bool:
        """ Responsible for uncasting a vote """
        session = get_session()
        try:
            delete_poll_vote_stmnt = (
                delete(cls)
                .where(
                    and_(
                        cls.user_id == vote_info.get('user_id'),
                        cls.vote_id == vote_info.get('vote_id'),
                        cls.option_id == vote_info.get('option_id')
                    )
                )
            )
            session.execute(delete_poll_vote_stmnt)
            session.commit()
            return True
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err
        pass
    
    @classmethod
    def change_vote(cls, vote_info: dict) -> bool:
        """ Responsible for changing a vote """
        session = get_session()
        try:
            update_vote_stmnt = (
                update(cls)
                .where(
                    and_(
                        cls.user_id == vote_info.get('user_id'),
                        cls.vote_id == vote_info.get('vote_id')
                    )
                )
                .values(option_id=vote_info.get('option_id'))
            )
            session.execute(update_vote_stmnt)
            session.commit()
            return True
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err
        pass