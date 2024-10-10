""" Class represents candidates name and information """
from sqlalchemy.sql import expression

from app.utils.engine import get_session
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy import Column, Integer, String, Date, select, update, Boolean, Enum, ForeignKey, DateTime, Text
from app.models.base import Base


class Candidates(Base):
    __tablename__ = 'candidates'
    candidate_id = Column(Integer, autoincrement=True, primary_key=True, nullable=False)
    name = Column(String(255), nullable=False)
    info = Column(Text, nullable=False)
    