from sqlalchemy import Column, Integer, select, update, VARCHAR, BINARY, Enum, Text, DateTime, TIMESTAMP, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import expression

from app.models.base import Base
from app.utils.engine import get_session

class AuditLog(Base):
    __tablename__ = "audit_log"
    log_id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(BINARY(16), nullable=False, unique=True)
    user_id = Column(Integer, nullable=False)
    event_id = Column(Integer, nullable=False)
    action = Column(VARCHAR(50), nullable=False)
    details = Column(VARCHAR(255), nullable=True)
    timestamp = Column(TIMESTAMP, nullable=False)
    