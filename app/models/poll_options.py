""" Class represent the shape of the table poll options that will be used for poll base votes """
from sqlalchemy import Column, Integer, update, ForeignKey, insert, delete, and_, VARCHAR
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy.orm import relationship

from app.models.base import Base
from app.utils.engine import get_session


class PollOption(Base):
    __tablename__ = 'poll_option'
    option_id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    event_id = Column(Integer, ForeignKey('vote_types.vote_type_id'), nullable=False)  # Reference to vote_types
    option_text = Column(VARCHAR(length=255), nullable=False)
    
    voting_event = relationship('VotingEvent', back_populates='poll_option', cascade="all, restrict")
    
    @classmethod
    def add_option(cls, poll_info: dict) -> bool:
        """ Responsible for adding new option"""
        session = get_session()
        try:
            new_poll_option_stmnt = (
                insert(cls).values(poll_info)
            )
            session.execute(new_poll_option_stmnt)
            session.commit()
            return True
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err
    @classmethod
    def delete_option(cls, poll_info: dict) -> bool:
        """ Function responsible for deleting an option """
        session = get_session()
        try:
            delete_option_stmnt = (
                delete(cls)
                .where(
                    and_(
                        cls.option_id == poll_info.get('option_id'),
                        cls.event_id == poll_info.get('event_id')
                    )
                )
            )
            session.execute(delete_option_stmnt)
            session.commit()
            return True
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err
        pass
    @classmethod
    def edit_option(cls, poll_info: dict) -> bool:
        """ Function responsible for editing an option in the poll voting type """
        session = get_session()
        try:
            edit_option_text_stmnt = (
                update(cls.option_text)
                .where(
                    and_(
                        cls.event_id == poll_info.get('event_id'),
                        cls.option_id == poll_info.get('option_id')
                    )
                )
            )
            session.execute(edit_option_text_stmnt)
            session.commit()
            return True
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            raise err