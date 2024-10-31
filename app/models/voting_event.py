""" Class represents each type of voting events and is also the form of data we expect in the database """

from sqlalchemy import Column, Integer, select, update, VARCHAR, BINARY, Enum, Text, DateTime, TIMESTAMP, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import expression

from app.models.base import Base
from app.utils.engine import get_session

class VotingEvent(Base):
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
    
    @classmethod
    def create_new_voting_event(cls):
        pass
    
    @classmethod
    def update_voting_event(cls):
        pass
    
    @classmethod
    def delete_voting_event(cls):
        pass
    
    @classmethod
    def get_voting_event(cls):
        pass
    