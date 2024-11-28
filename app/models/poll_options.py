""" Class represent the shape of the table poll options that will be used for poll base votes """

# pylint: disable=R0801

from sqlalchemy import (
    Column,
    Integer,
    update,
    ForeignKey,
    insert,
    delete,
    and_,
    VARCHAR,
    select,
)
from sqlalchemy.exc import IntegrityError, DataError, OperationalError, DatabaseError
from sqlalchemy.orm import relationship

from app.models.base import Base
from app.utils.engine import get_session


class PollOption(Base):  # pylint: disable=R0903
    """Class to represent the poll options table"""

    __tablename__ = "poll_option"

    option_id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    event_id = Column(Integer, ForeignKey("voting_event.event_id"), nullable=False)
    option_text = Column(VARCHAR(length=255), nullable=False)

    voting_event = relationship("VotingEvent", back_populates="poll_option")

    def to_dict(self) -> dict:
        """Converts the model instance to a dictionary."""
        return {
            "option_id": self.option_id,
            "event_id": self.event_id,
            "option_text": self.option_text,
        }


class PollOperations:
    """Class to handle poll operations"""

    @classmethod
    def get_poll_options(cls, event_id: int):  # pylint: disable=C0116
        session = get_session()
        try:
            poll_options = (
                session.query(PollOption).where(PollOption.event_id == event_id).all()
            )
            return [poll_option.to_dict() for poll_option in poll_options]
        except (
            DatabaseError,
            OperationalError,
        ) as err:
            raise err
        finally:
            session.close()

    @classmethod
    def add_option(cls, poll_info: dict):  # pylint: disable=C0116
        session = get_session()
        try:
            new_poll_option_statement = insert(PollOption).values(poll_info)
            session.execute(new_poll_option_statement)
            session.commit()
        except (IntegrityError, DataError, OperationalError, DatabaseError) as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @classmethod
    def delete_option(cls, poll_info: dict):  # pylint: disable=C0116
        session = get_session()
        try:
            delete_option_statement = delete(PollOption).where(
                and_(
                    PollOption.option_id == poll_info.get("option_id"),
                    PollOption.event_id == poll_info.get("event_id"),
                )
            )
            session.execute(delete_option_statement)
            session.commit()
            return True
        except (IntegrityError, DataError, OperationalError, DatabaseError) as err:
            session.rollback()
            raise err
        finally:
            session.close()

    @classmethod
    def edit_option(cls, poll_info: dict):  # pylint: disable=C0116
        session = get_session()
        try:
            edit_option_statement = (
                update(PollOption)
                .where(
                    PollOption.event_id == poll_info.get("event_id"),
                    PollOption.option_id == poll_info.get("option_id"),
                )
                .values(option_text=poll_info.get("option_text"))
            )

            session.execute(edit_option_statement)
            session.commit()
        except (IntegrityError, DataError, DatabaseError, OperationalError) as err:
            session.rollback()
            raise err
        finally:
            session.close()

    @classmethod
    def is_poll_option_id_exists(cls, option_id: int) -> bool:
        """
        Check if the poll option id exists.

        Args:
            option_id (int): ID of the poll option to check

        Returns:
            bool: True if option exists, False otherwise

        Raises:
            DatabaseError: If database operation fails
            OperationalError: If database is unreachable
        """
        session = get_session()
        try:
            poll_option_statement = select(PollOption).where(
                PollOption.option_id == option_id
            )
            result = session.execute(poll_option_statement).fetchone()
            return result is not None
        except (DatabaseError, OperationalError) as err:
            raise err
        finally:
            session.close()


class UserPollOptionOperation:  # pylint: disable=R0903
    """User Related Poll Option Operations"""

    @classmethod
    def get_all_poll_options(cls, event_id: int):  # pylint: disable=C0116
        session = get_session()
        try:
            poll_options_statement = select(PollOption).where(
                PollOption.event_id == event_id
            )
            return session.execute(poll_options_statement).fetchall()
        except (
            DatabaseError,
            OperationalError,
        ) as err:
            raise err
        finally:
            session.close()
