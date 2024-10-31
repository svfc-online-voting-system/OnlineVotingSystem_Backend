""" This module contains the AuditLog model """
from sqlalchemy import Column, Integer, VARCHAR, BINARY, TIMESTAMP

from app.models.base import Base


class AuditLog(Base):  # pylint: disable=R0903
    """AuditLog model class that represents the audit_log table."""
    __tablename__ = "audit_log"
    log_id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(BINARY(16), nullable=False, unique=True)
    user_id = Column(Integer, nullable=False)
    event_id = Column(Integer, nullable=False)
    action = Column(VARCHAR(50), nullable=False)
    details = Column(VARCHAR(255), nullable=True)
    timestamp = Column(TIMESTAMP, nullable=False)
    