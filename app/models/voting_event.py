""" Class represents each type of voting events and is also the form of data we expect in the database """

# pylint: disable=R0801

from uuid import UUID
from sqlalchemy import (
    Column,
    Integer,
    Text,
    DateTime,
    TIMESTAMP,
    Boolean,
    and_,
    select,
    update,
    ForeignKey, CheckConstraint, text, String, LargeBinary,
)
from sqlalchemy.exc import OperationalError, IntegrityError, DatabaseError, DataError
from sqlalchemy.orm import relationship

from app.exception.voting_event_exception import VotingEventDoesNotExists
from app.models.base import Base
from app.models.poll_options import PollOption
from app.models.user import User
from app.utils.engine import get_session


class VotingEvent(Base):
    """
    SQLAlchemy model for the 'voting_event' table with PostgreSQL compatibility.
    """
    
    __tablename__ = "voting_event"
    
    event_id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(LargeBinary(16), nullable=False, unique=True)  # Maps to BYTEA
    event_type = Column(
        String,
        CheckConstraint("event_type IN ('poll', 'electoral')", "voting_event_event_type_check"), nullable=False,
    )
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    start_date = Column(
        DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    end_date = Column(DateTime, nullable=False)
    status = Column(
        String,
        CheckConstraint(
            sqltext="status IN ('upcoming', 'active', 'completed', 'cancelled')",
            name="voting_event_status_check"
        ), server_default=text("'upcoming'"), nullable=False
    )
    created_by = Column(
        Integer, ForeignKey("user.user_id", onupdate="CASCADE", ondelete="NO ACTION"), nullable=False
    )
    created_at = Column(
        TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    last_modified_at = Column(
        TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    approved = Column(Boolean, nullable=False, server_default=text("false"))
    is_deleted = Column(Boolean, nullable=False, server_default=text("false"))
    
    user = relationship(
        "User",
        back_populates="voting_event",
        cascade="save-update, merge, expunge, refresh-expire",
    )
    poll_option = relationship(
        "PollOption",
        back_populates="voting_event",
        cascade="all, delete-orphan",
    )
    
    def to_dict(self):
        """Converts the model to a dictionary."""
        return {
            "event_id": self.event_id,
            "uuid": UUID(bytes=self.uuid).hex,  # Convert binary UUID to string
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "status": self.status,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "last_modified_at": self.last_modified_at,
            "approved": self.approved,
            "is_deleted": self.is_deleted,
        }
    
    @classmethod
    def uuid_to_bin(cls, uuid_str):
        """Convert string UUID to binary format"""
        return UUID(uuid_str).bytes
    
    @classmethod
    def bin_to_uuid(cls, uuid_bin):
        """Convert binary UUID to string format"""
        return str(UUID(bytes=uuid_bin))
    
    @classmethod
    def format_uuid(cls, uuid_str):
        """Format UUID string with hyphens"""
        return (
            f"{uuid_str[:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-"
            f"{uuid_str[16:20]}-{uuid_str[20:]}"
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
        except (OperationalError, IntegrityError, DatabaseError, DataError) as err:
            session.rollback()
            raise err
        finally:
            session.close()

    @classmethod
    def update_voting_event(cls):  # pylint: disable=C0116
        pass

    @classmethod
    def delete_voting_events(cls, event_ids: list[int], user_id: int):
        """
        Performs a soft delete of one or multiple voting events by setting is_deleted to True.

        Args:
            event_ids (list[int]): List of event IDs to delete
            user_id (int): ID of the user who created the events

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
                        VotingEvent.event_id.in_(event_ids),
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
    def get_voting_event(cls, event_id, event_type, user_id):
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
                    VotingEvent.created_by == user_id,
                )
            )
        ).fetchone()
        if voting_event is None:
            raise VotingEventDoesNotExists("Voting event does not exists")
        return voting_event

    @classmethod
    def get_voting_event_by_uuid(cls, uuid_str, event_type: str):
        """Retrieves a specific voting event from the database based on UUID and type."""
        session = get_session()
        try:
            uuid_bin = VotingEvent.uuid_to_bin(uuid_str)

            result = session.execute(
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
                    PollOption.option_id,
                    PollOption.option_text,
                    User.username,
                )
                .outerjoin(PollOption, VotingEvent.event_id == PollOption.event_id)
                .join(User, VotingEvent.created_by == User.user_id)
                .where(
                    and_(
                        VotingEvent.uuid == uuid_bin,
                        VotingEvent.event_type == event_type,
                        VotingEvent.is_deleted.is_(False),
                    )
                )
            ).fetchall()

            if not result:
                raise VotingEventDoesNotExists("Voting event does not exists")

            first_row = result[0]

            poll_options = [
                {"option_id": row.option_id, "option_text": row.option_text}
                for row in result
                if row.option_id is not None
            ]

            return {
                "uuid": VotingEvent.format_uuid(UUID(bytes=first_row.uuid).hex),
                "title": first_row.title,
                "description": first_row.description,
                "start_date": first_row.start_date,
                "end_date": first_row.end_date,
                "status": first_row.status,
                "created_by": first_row.created_by,
                "created_at": first_row.created_at,
                "last_modified_at": first_row.last_modified_at,
                "event_type": first_row.event_type,
                "poll_options": poll_options,
                "creator_username": first_row.username,
            }
        except (OperationalError, DatabaseError, DataError) as err:
            raise err
        finally:
            session.close()

    @classmethod
    def get_event_id_from_uuid(cls, uuid_str, event_type):
        """Retrieves the event ID from the UUID."""
        session = get_session()
        try:
            uuid_bin = VotingEvent.uuid_to_bin(uuid_str)
            result = session.execute(
                select(VotingEvent.event_id).where(
                    and_(
                        VotingEvent.uuid == uuid_bin,
                        VotingEvent.event_type == event_type,
                    )
                )
            ).fetchone()
            return result.event_id if result else None
        except (OperationalError, DatabaseError) as err:
            raise err
        finally:
            session.close()


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
    def get_all_voting_events_by(cls, voting_event_type=None):
        """Retrieves all active voting events from the database with user details."""
        session = get_session()
        try:
            query = select(
                VotingEvent,
                User.username,
                User.firstname,
                User.lastname,
                User.user_id,
                User.uuid,
            ).join(User, VotingEvent.created_by == User.user_id)
            if voting_event_type and voting_event_type != "all":
                query = query.where(VotingEvent.event_type == voting_event_type)
            results = session.execute(query).all()
            voting_events_list = []
            for result in results:
                event = result[0]  # VotingEvent object
                username = result[1]
                full_name = f"{result[2]} {result[3]}"
                user_id = result[4]
                user_uuid = UUID(bytes=result[5]).hex  # type: ignore

                event_dict = event.to_dict()
                event_dict.update(
                    {
                        "creator_username": username,
                        "creator_fullname": full_name,
                        "creator_id": user_id,
                        "creator_uuid": user_uuid,
                    }
                )
                voting_events_list.append(event_dict)
            return voting_events_list
        except (OperationalError, DatabaseError) as err:
            raise err
        finally:
            session.close()


class UserOperations:  # pylint: disable=R0903
    """Class containing operations for users."""

    @classmethod
    def get_voting_events_by(cls, voting_event_type=None, voting_status=None):
        """Retrieves voting events based on type and status."""
        session = get_session()
        try:
            query = (
                select(
                    VotingEvent,
                    User.firstname,
                    User.lastname,
                    VotingEvent.uuid.label("event_uuid"),
                    User.uuid.label("user_uuid"),
                )
                .join(User, VotingEvent.created_by == User.user_id)
                .where(
                    and_(
                        VotingEvent.is_deleted.is_(False),
                        VotingEvent.approved.is_(True),
                    )
                )
            )

            if voting_event_type and voting_event_type != "all":
                query = query.where(VotingEvent.event_type == voting_event_type)

            if voting_status and voting_status != "all":
                query = query.where(VotingEvent.status == voting_status)

            results = session.execute(query).all()
            voting_events_list = []

            for result in results:
                event = result[0]  # VotingEvent object
                event_uuid_bytes = result.event_uuid
                user_uuid_bytes = result.user_uuid
                hex_uuid = UUID(bytes=event_uuid_bytes).hex

                voting_events_list.append(
                    {
                        "id": event.event_id,
                        "event_uuid": (
                            f"{hex_uuid[:8]}-"
                            f"{hex_uuid[8:12]}-"
                            f"{hex_uuid[12:16]}-"
                            f"{hex_uuid[16:20]}-"
                            f"{hex_uuid[20:]}"
                        ),
                        "title": event.title,
                        "description": event.description,
                        "event_type": event.event_type,
                        "status": event.status,
                        "start_date": event.start_date,
                        "end_date": event.end_date,
                        "creator_firstname": result.firstname,
                        "creator_uuid": UUID(bytes=user_uuid_bytes).hex,  # type: ignore
                        "created_at": event.created_at,
                        "last_modified_at": event.last_modified_at,
                    }
                )
            return voting_events_list

        except (OperationalError, DatabaseError, DataError) as err:
            raise err
        finally:
            session.close()
