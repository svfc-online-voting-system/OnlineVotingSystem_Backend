""" Represents the model ballots cast """
from datetime import datetime
from sqlalchemy import Column, Integer, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy.sql.operators import or_
from app.models.base import Base


class Ballots(Base):
    __tablename__ = 'ballots'
    ballot_id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    user_id = Column(Integer, ForeignKey('user.user_id'), nullable=False)
    vote_type_id = Column(Integer, ForeignKey('vote_types.vote_type_id'), nullable=False)
    submitted_at = Column(DateTime, nullable=False, default=datetime.now())
    user = relationship('User', back_populates='ballots', uselist=False, cascade='all, delete-orphan')
    vote_types = relationship('VoteTypes', back_populates='ballots', uselist=False, cascade='all, delete-orphan')