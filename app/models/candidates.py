""" Class represents candidates name and information """
from sqlalchemy import Column, Integer, Text, VARCHAR
from sqlalchemy.orm import relationship

from app.models.base import Base


class Candidates(Base):
    __tablename__ = 'candidates'
    candidate_id = Column(Integer, autoincrement=True, primary_key=True, nullable=False)
    name = Column(VARCHAR(length=255), nullable=False)
    info = Column(Text, nullable=False)
    candidates = relationship('ElectoralVotes', back_populates='candidates', uselist=True, cascade='all, delete-orphan')
    