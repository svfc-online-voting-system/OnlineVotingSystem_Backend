
from app.models.base import Base
from sqlalchemy import Column, Integer, ForeignKey
from sqlalchemy.orm import relationship

class ElectoralVotes(Base):
    __tablename__ = 'electoral_votes'
    electoral_vote_id = Column(Integer, primary_key=True, autoincrement=True)
    vote_id = Column(Integer, ForeignKey('votes.vote_id'), nullable=False)
    candidate_id = Column(Integer, ForeignKey('candidates.candidate_id'), nullable=False)
    candidates = relationship('Candidates', back_populates='electoral_votes', uselist=False, cascade='all, delete-orphan')
    votes = relationship('Votes', back_populates='electoral_votes', uselist=False, cascade='all, delete-orphan')