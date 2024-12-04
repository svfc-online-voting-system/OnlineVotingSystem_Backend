""" This module contains the AuditLog model """

from sqlalchemy import Column, Integer, VARCHAR, TIMESTAMP, UniqueConstraint, LargeBinary, ForeignKey
from sqlalchemy.exc import OperationalError, IntegrityError, DatabaseError, DataError

from app.models.base import Base
from app.utils.engine import get_session


class AuditLog(Base):  # pylint: disable=R0903
    """AuditLog model class that represents the audit_log table."""
    
    __tablename__ = "audit_log"
    
    log_id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(LargeBinary(16), nullable=False, unique=True)  # Use LargeBinary for bytea
    user_id = Column(Integer,
                     ForeignKey("user.user_id", onupdate="CASCADE", ondelete="NO ACTION"),
                     nullable=False)
    event_id = Column(Integer,
                      ForeignKey("voting_event.event_id", onupdate="CASCADE", ondelete="NO ACTION"),
                      nullable=False)
    action = Column(VARCHAR(50), nullable=False)
    details = Column(VARCHAR(255), nullable=True)
    timestamp = Column(TIMESTAMP, nullable=False, default="CURRENT_TIMESTAMP")  # PostgreSQL's timestamp default
    
    __table_args__ = (
        UniqueConstraint("uuid", name="audit_log_uuid_key"),
    )


class PollRelatedLogOperations:  # pylint: disable=R0903
    """Class to handle poll related log operations such as creating, updating, deleting and getting poll related logs"""

    @staticmethod
    def create_poll_related_log(log_data: dict) -> None:
        """Create a new poll related log"""
        session = get_session()
        try:
            new_poll_related_log = AuditLog(
                uuid=log_data.get("uuid"),
                user_id=log_data.get("user_id"),
                event_id=log_data.get("event_id"),
                action=log_data.get("action"),
                details=log_data.get("details"),
                timestamp=log_data.get("timestamp"),
            )
            session.add(new_poll_related_log)
            session.commit()
        except (
            OperationalError,
            DatabaseError,
            IntegrityError,
            DataError,
        ) as err:
            session.rollback()
            raise err
        finally:
            session.close()
