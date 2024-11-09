""" Class represents each type of voting events and is also the form of data we expect in the database """

from sqlalchemy import (
    Column,
    Integer,
    VARCHAR,
    BINARY,
    Enum,
    Text,
    DateTime,
    TIMESTAMP,
    Boolean,
    and_,
    select,
    update,
    ForeignKey,
)
from sqlalchemy.exc import OperationalError, IntegrityError, DatabaseError, DataError
from sqlalchemy.orm import relationship

from app.exception.voting_event_exception import VotingEventDoesNotExists
from app.models.base import Base
from app.utils.engine import get_session


class VotingEvent(Base):  # pylint: disable=R0903
    """
    SQLAlchemy model representing a voting event in the database.

    Contains event details like type (poll/electoral), title, description, dates,
    status, and approval state. Links to User model through created_by field.
    Tracks event lifecycle with timestamps and soft deletion.
    """

    __tablename__ = "voting_event"
    event_id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(BINARY(16), nullable=False, unique=True)
    event_type = Column(Enum("poll", "electoral"), nullable=False)
    title = Column(VARCHAR(255), nullable=False)
    description = Column(Text, nullable=False)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    status = Column(
        Enum("upcoming", "active", "completed", "cancelled"), nullable=False
    )
    created_by = Column(ForeignKey("user.user_id"), nullable=False)
    created_at = Column(TIMESTAMP, nullable=False)
    last_modified_at = Column(TIMESTAMP, nullable=False)
    approved = Column(Boolean, nullable=False)
    is_deleted = Column(Boolean, nullable=False, default=False)

    user = relationship(
        "User",
        back_populates="voting_event",
        cascade="save-update, merge, expunge, refresh-expire",
    )


class VotingEventOperations:
    """
    Provides operations for managing voting events in the database.

    Handles CRUD operations for voting events including creating new events,
    updating existing ones, soft deleting events, and retrieving event details.
    Uses SQLAlchemy for database interactions and includes error handling for
    database operations.
    """

    @classmethod
    def create_new_voting_event(cls, poll_data: dict):
        """
        Creates a new voting event in the database from the provided poll data.

        Args:
            poll_data (dict): Dictionary containing voting event details including uuid, title,
                            dates, status, and other required fields.

        Returns:
            int: The event_id of the newly created voting event.

        Raises:
            OperationalError: If there is a problem with database operations.
            IntegrityError: If there is a violation of database constraints.
            DatabaseError: If there is a general database error.
            DataError: If there is an issue with the data format.
        """
        session = get_session()
        try:
            new_voting_event = VotingEvent(
                uuid=poll_data.get("uuid"),
                created_by=poll_data.get("created_by"),
                title=poll_data.get("title"),
                created_at=poll_data.get("created_at"),
                last_modified_at=poll_data.get("last_modified_at"),
                start_date=poll_data.get("start_date"),
                end_date=poll_data.get("end_date"),
                status=poll_data.get("status"),
                approved=poll_data.get("approved"),
                event_type=poll_data.get("event_type"),
                description=poll_data.get("description"),
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
    def delete_voting_event(cls, event_id, user_id):
        """
        Performs a soft delete of a voting event by setting is_deleted to True.

        Args:
            event_id (int): ID of the voting event to delete
            user_id (int): ID of the user who created the event

        Raises:
            OperationalError: If there is a problem with database operations
            IntegrityError: If there is a violation of database constraints
            DatabaseError: If there is a general database error
            DataError: If there is an issue with the data format
        """
        session = get_session()
        try:
            session.execute(
                update(VotingEvent)
                .values(is_deleted=True)
                .where(
                    and_(
                        VotingEvent.event_id == event_id,
                        VotingEvent.created_by == user_id,
                    )
                )
            )
            session.commit()
        except (OperationalError, IntegrityError, DatabaseError, DataError) as err:
            session.rollback()
            raise err
        finally:
            session.close()

    @classmethod
    def get_voting_event(cls, event_id, event_type):
        """
        Retrieves a specific voting event from the database based on event ID and type.

        Args:
            event_id: ID of the voting event to retrieve
            event_type: Type of the voting event ('poll' or 'electoral')

        Returns:
            Row object containing the voting event details including uuid, title, description,
            dates, status and other fields

        Raises:
            VotingEventDoesNotExists: If no matching active voting event is found
        """
        session = get_session()
        voting_event = session.execute(
            select(
                VotingEvent.uuid,
                VotingEvent.title,
                VotingEvent.description,
                VotingEvent.start_date,
                VotingEvent.end_date,
                VotingEvent.status,
                VotingEvent.created_by,
                VotingEvent.created_at,
                VotingEvent.last_modified_at,
                VotingEvent.approved,
                VotingEvent.event_type,
            ).where(
                and_(
                    VotingEvent.event_id == event_id,
                    VotingEvent.is_deleted.is_(False),
                    VotingEvent.event_type == event_type,
                )
            )
        ).fetchone()
        if voting_event is None:
            raise VotingEventDoesNotExists("Voting event does not exists")
        return voting_event


class AdminOperations:
    """
    Class containing administrative operations for managing voting events.

    Methods:
        approve_vote: Validates and approves a vote for a given voting event.
        get_all_voting_events: Retrieves all active voting events from the database.
    """

    @classmethod
    def approve_vote(cls, voting_event_id: int):
        """Service that will call and validate the approval of the vote"""

    @classmethod
    def get_all_voting_events(cls):
        """
        Retrieves all non-deleted voting events from the database.

        Returns:
            list: A list of voting events containing uuid, title, description, dates, status,
                creator info, timestamps, approval status and event type.
        """
        session = get_session()
        voting_events = session.execute(
            select(
                VotingEvent.uuid,
                VotingEvent.title,
                VotingEvent.description,
                VotingEvent.start_date,
                VotingEvent.end_date,
                VotingEvent.status,
                VotingEvent.created_by,
                VotingEvent.created_at,
                VotingEvent.last_modified_at,
                VotingEvent.approved,
                VotingEvent.event_type,
            ).where(VotingEvent.is_deleted.is_(False))
        ).fetchall()
        return voting_events
