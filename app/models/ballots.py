""" Represents the model ballots cast """
from datetime import datetime

from sqlalchemy import Column, Integer, String, Date, select, update, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship, joinedload
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy.sql import expression
from sqlalchemy.sql.operators import or_
from app.models.base import Base


class Ballots(Base):
    __tablename__ = 'ballots'
    ballot_id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    user_id = Column(Integer, ForeignKey('user.user_id'), nullable=False)
    vote_type_id = Column(Integer, ForeignKey('vote_types.vote_type_id'), nullable=False)
    submitted_at = Column(DateTime, nullable=False, default=datetime.now())