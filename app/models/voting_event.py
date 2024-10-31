""" Class represents each type of voting events and is also the form of data we expect in the database """

from sqlalchemy import (
    Column, Integer, VARCHAR, BINARY, Enum, Text, DateTime, TIMESTAMP, Boolean
)
from sqlalchemy.exc import OperationalError, IntegrityError, DatabaseError, DataError
from sqlalchemy.orm import relationship

from app.models.base import Base
from app.utils.engine import get_session


class VotingEvent(Base):  # pylint: disable=R0903
    """ Class represents each type of voting events and is also the form of data we expect in the database """
    __tablename__ = "voting_event"
    event_id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(BINARY(16), nullable=False, unique=True)
    event_type = Column(Enum("poll", "electoral"), nullable=False)
    title = Column(VARCHAR(255), nullable=False)
    description = Column(Text, nullable=False)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    status = Column(Enum('upcoming', 'active', 'completed', 'cancelled'), nullable=False)
    created_by = Column(Integer, nullable=False) # This is a foreign key that we'll reference later
    created_at = Column(TIMESTAMP, nullable=False)
    last_modified_at = Column(TIMESTAMP, nullable=False)
    approved = Column(Boolean, nullable=False)
    
    user = relationship('User', back_populates='voting_event', cascade="all, restrict")
    

class VotingEventOperations:
    """
    Class to handle voting event operations such as creating, updating,
    deleting and getting voting events
    """
    @classmethod
    def create_new_voting_event(cls, poll_data: dict):  # pylint: disable=C0116
        session = get_session()
        try:
            new_voting_event = VotingEvent(
                uuid=poll_data.get('uuid'),
                created_by=poll_data.get('user_id'),
                title=poll_data.get('title'),
                created_at=poll_data.get('created_at'),
                last_modified_at=poll_data.get('last_modified_at'),
                start_date=poll_data.get('start_date'),
                end_date=poll_data.get('end_date'),
                status=poll_data.get('status'),
                approved=poll_data.get('approved'),
                event_type=poll_data.get('event_type'),
                description=poll_data.get('description')
            )
            session.add(new_voting_event)
            session.commit()
            return new_voting_event.event_id
        except (OperationalError, IntegrityError, DatabaseError, DataError) as err:
            session.rollback()
            raise err
        finally:
            session.close()
    
    @classmethod
    def update_voting_event(cls):  # pylint: disable=C0116
        pass
    
    @classmethod
    def delete_voting_event(cls):  # pylint: disable=C0116
        pass
    
    @classmethod
    def get_voting_event(cls):  # pylint: disable=C0116
        pass
    