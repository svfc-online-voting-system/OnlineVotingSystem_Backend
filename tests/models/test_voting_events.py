"""Test cases for voting events model."""

# pylint: disable=W0621
# pylint: disable=C0116
# pylint: disable=C0103

from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest
from sqlalchemy import Update, update, and_
from sqlalchemy.exc import OperationalError, IntegrityError, DatabaseError, DataError

from app.models.voting_event import VotingEventOperations, VotingEvent


@pytest.fixture
def mock_session():
    """Mock the session object."""
    with patch("app.models.voting_event.get_session") as mock:
        session = Mock()
        mock.return_value = session
        yield session


class TestVoteEventCreation:
    """Test for voting event creation."""

    def test_create_new_voting_event_success(self, mock_session):
        # Arrange
        mock_session.add.return_value = None
        mock_session.commit.return_value = None

        poll_data = {
            "uuid": b"1234567890123456",
            "created_by": 1,
            "title": "Test Voting Event",
            "created_at": datetime.now(),
            "last_modified_at": datetime.now(),
            "start_date": datetime.now(),
            "end_date": datetime.now() + timedelta(days=7),
            "status": "upcoming",
            "approved": False,
            "event_type": "poll",
            "description": "Test description",
        }

        # Act
        VotingEventOperations.create_new_voting_event(poll_data)

        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

    def test_create_new_voting_event_operational_error(self, mock_session):
        # Arrange
        mock_session.add.side_effect = OperationalError(
            "Database connection error", None, None  # type: ignore
        )
        poll_data = {
            "uuid": b"1234567890123456",
            "created_by": 1,
            "title": "Test Event",
            "created_at": datetime.now(),
            "last_modified_at": datetime.now(),
            "start_date": datetime.now(),
            "end_date": datetime.now() + timedelta(days=1),
            "status": "upcoming",
            "approved": False,
            "event_type": "poll",
            "description": "Test Description",
        }

        # Act & Assert
        with pytest.raises(OperationalError):
            VotingEventOperations.create_new_voting_event(poll_data)

        mock_session.add.assert_called_once()
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()

    def test_create_new_voting_event_integrity_error(self, mock_session):
        # Arrange
        mock_session.add.side_effect = IntegrityError(None, None, None)  # type: ignore
        poll_data = {
            "uuid": b"1234567890123456",
            "created_by": 1,
            "title": "Test Event",
            "created_at": datetime.now(),
            "last_modified_at": datetime.now(),
            "start_date": datetime.now(),
            "end_date": datetime.now() + timedelta(days=1),
            "status": "upcoming",
            "approved": False,
            "event_type": "poll",
            "description": "Test description",
        }

        # Act & Assert
        with pytest.raises(IntegrityError):
            VotingEventOperations.create_new_voting_event(poll_data)

        mock_session.add.assert_called_once()
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()

    def test_create_new_voting_event_database_error(self, mock_session):
        # Arrange
        mock_session.add.side_effect = DatabaseError(None, None, None)  # type: ignore
        poll_data = {
            "uuid": b"1234567890123456",
            "created_by": 1,
            "title": "Test Event",
            "created_at": "2023-01-01 00:00:00",
            "last_modified_at": "2023-01-01 00:00:00",
            "start_date": "2023-01-02 00:00:00",
            "end_date": "2023-01-03 00:00:00",
            "status": "upcoming",
            "approved": False,
            "event_type": "poll",
            "description": "Test description",
        }

        # Act & Assert
        with pytest.raises(DatabaseError):
            VotingEventOperations.create_new_voting_event(poll_data)

        mock_session.add.assert_called_once()
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()

    def test_create_new_voting_event_raises_data_error(self, mock_session):
        # Arrange
        mock_session.add.side_effect = DataError(None, None, None)  # type: ignore
        mock_session.commit.side_effect = DataError(None, None, None)  # type: ignore

        invalid_poll_data = {
            "uuid": "invalid_uuid",
            "created_by": "invalid_user_id",
            "title": "Test Event",
            "created_at": "invalid_date",
            "last_modified_at": "invalid_date",
            "start_date": "invalid_date",
            "end_date": "invalid_date",
            "status": "invalid_status",
            "approved": "invalid_boolean",
            "event_type": "invalid_type",
            "description": "Test Description",
        }

        # Act & Assert
        with pytest.raises(DataError):
            VotingEventOperations.create_new_voting_event(invalid_poll_data)

        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()

    def test_create_new_voting_event_with_missing_optional_fields(self, mock_session):
        poll_data = {
            "uuid": b"1234567890123456",
            "created_by": 1,
            "title": "Test Event",
            "created_at": datetime.now(),
            "last_modified_at": datetime.now(),
            "start_date": datetime.now(),
            "end_date": datetime.now() + timedelta(days=1),
            "status": "upcoming",
            "event_type": "poll",
        }

        mock_session.add.return_value = None
        mock_session.commit.return_value = None

        new_event = Mock()
        new_event.event_id = 1
        mock_session.add.side_effect = lambda x: setattr(
            x, "event_id", new_event.event_id
        )

        VotingEventOperations.create_new_voting_event(poll_data)

        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

        added_event = mock_session.add.call_args[0][0]
        assert isinstance(added_event, VotingEvent)
        assert added_event.approved is None
        assert added_event.description is None

    def test_create_new_voting_event_sets_all_fields(self, mock_session):
        # Arrange
        poll_data = {
            "uuid": b"1234567890123456",
            "created_by": 1,
            "title": "Test Event",
            "created_at": datetime.now(),
            "last_modified_at": datetime.now(),
            "start_date": datetime.now(),
            "end_date": datetime.now() + timedelta(days=1),
            "status": "upcoming",
            "approved": False,
            "event_type": "poll",
            "description": "Test description",
        }
        mock_session.add.return_value = None
        mock_session.commit.return_value = None

        # Act
        VotingEventOperations.create_new_voting_event(poll_data)

        # Assert
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        added_event = mock_session.add.call_args[0][0]
        assert isinstance(added_event, VotingEvent)
        for key, value in poll_data.items():
            assert getattr(added_event, key) == value

    def test_create_new_voting_event(self, mock_session):
        # Arrange
        poll_data = {
            "uuid": b"1234567890123456",
            "created_by": 1,
            "title": "Test Event",
            "created_at": "2023-01-01 00:00:00",
            "last_modified_at": "2023-01-01 00:00:00",
            "start_date": "2023-01-02 00:00:00",
            "end_date": "2023-01-03 00:00:00",
            "status": "upcoming",
            "approved": False,
            "event_type": "poll",
            "description": "Test description",
        }
        mock_session.add.return_value = None
        mock_session.commit.return_value = None
        mock_voting_event = Mock()
        mock_voting_event.event_id = 1
        mock_session.add.side_effect = lambda x: setattr(x, "event_id", 1)

        # Act
        VotingEventOperations.create_new_voting_event(poll_data)

        # Assert
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

    def test_create_new_voting_event_session_closure_on_exception(self, mock_session):
        with patch(
            "app.models.voting_event.VotingEvent"
        ) as mock_voting_event, patch.object(
            mock_session, "add", side_effect=OperationalError(None, None, None)  # type: ignore
        ):

            mock_voting_event.return_value = Mock()
            poll_data = {
                "uuid": b"1234567890123456",
                "created_by": 1,
                "title": "Test Event",
                "created_at": "2023-01-01 00:00:00",
                "last_modified_at": "2023-01-01 00:00:00",
                "start_date": "2023-01-02 00:00:00",
                "end_date": "2023-01-03 00:00:00",
                "status": "upcoming",
                "approved": False,
                "event_type": "poll",
                "description": "Test description",
            }

            with pytest.raises(OperationalError):
                VotingEventOperations.create_new_voting_event(poll_data)

            mock_session.rollback.assert_called_once()
            mock_session.close.assert_called_once()

    def test_create_new_voting_event_rollback_on_exception(self, mock_session):
        # Arrange
        poll_data = {
            "uuid": b"1234567890123456",
            "created_by": 1,
            "title": "Test Event",
            "created_at": "2023-01-01 00:00:00",
            "last_modified_at": "2023-01-01 00:00:00",
            "start_date": "2023-01-02 00:00:00",
            "end_date": "2023-01-03 00:00:00",
            "status": "upcoming",
            "approved": False,
            "event_type": "poll",
            "description": "Test Description",
        }
        mock_session.add.side_effect = OperationalError(None, None, None)  # type: ignore

        # Act
        with pytest.raises(OperationalError):
            VotingEventOperations.create_new_voting_event(poll_data)

        # Assert
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()


class TestEventDeletion:
    def test_delete_voting_event_success(self, mock_session):
        # Arrange
        event_id = 1
        user_id = 1
        mock_session.execute.return_value = None
        mock_session.commit.return_value = None

        # Act
        VotingEventOperations.delete_voting_event(event_id, user_id)

        # Assert
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

        # Check if the correct SQL update was executed
        update_call = mock_session.execute.call_args[0][0]
        assert isinstance(update_call, Update)
        assert str(update_call.table) == "voting_event"
        assert list(update_call._values.values())[0].value == True
        assert (
            str(update_call._where_criteria)
            == "voting_event.event_id = :event_id_1 AND voting_event.created_by = :created_by_1"
        )

    def test_delete_non_existent_voting_event(self, mock_session):
        # Arrange
        event_id = 999
        user_id = 1
        mock_session.execute.return_value = None
        mock_session.commit.return_value = None

        # Act
        VotingEventOperations.delete_voting_event(event_id, user_id)

        # Assert
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

        # Check that the correct SQL update was executed
        update_call = mock_session.execute.call_args[0][0]
        assert isinstance(update_call, Update)
        assert update_call.table == VotingEvent.__table__
        assert update_call.compile().params == {"is_deleted": True}
        assert (
            str(update_call._where_criteria[0])
            == f"voting_event.event_id = {event_id} AND voting_event.created_by = {user_id}"
        )

    def test_delete_voting_event_mismatched_user_id(self, mock_session):
        # Arrange
        event_id = 1
        user_id = 2
        mismatched_user_id = 3
        mock_session.execute.return_value = None
        mock_session.commit.return_value = None

        # Act
        VotingEventOperations.delete_voting_event(event_id, mismatched_user_id)

        # Assert
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

        # Check that the update was called with the correct parameters
        update_call = mock_session.execute.call_args[0][0]
        assert isinstance(update_call, Update)
        assert update_call.table == VotingEvent.__table__
        assert update_call._values == {"is_deleted": True}
        assert (
            str(update_call._where_criteria[0])
            == f"voting_event.event_id = {event_id} AND voting_event.created_by = {mismatched_user_id}"
        )

    def test_delete_already_deleted_voting_event(self, mock_session):
        # Arrange
        event_id = 1
        user_id = 1
        mock_session.execute.return_value = None
        mock_session.commit.return_value = None

        # Mock the update operation to simulate no rows affected
        mock_execute_result = Mock()
        mock_execute_result.rowcount = 0
        mock_session.execute.return_value = mock_execute_result

        # Act
        VotingEventOperations.delete_voting_event(event_id, user_id)

        # Assert
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

        # Verify that the update operation was called with the correct parameters
        update_call = mock_session.execute.call_args[0][0]
        assert isinstance(update_call, Update)
        assert update_call.table == VotingEvent.__table__
        assert update_call._values == {"is_deleted": True}
        assert str(update_call._where_criteria) == str(
            and_(VotingEvent.event_id == event_id, VotingEvent.created_by == user_id)
        )

    def test_delete_voting_event_with_invalid_event_id_type(self, mock_session):
        # Arrange
        invalid_event_id = "invalid_id"
        user_id = 1

        # Act & Assert
        with pytest.raises(TypeError):
            VotingEventOperations.delete_voting_event(invalid_event_id, user_id)

        mock_session.execute.assert_not_called()
        mock_session.commit.assert_not_called()
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()

    def test_delete_voting_event_invalid_user_id_type(self, mock_session):
        # Arrange
        event_id = 1
        invalid_user_id = "invalid_user_id"
        mock_session.execute.side_effect = TypeError(
            "Invalid data type for event_id or user_id"
        )

        # Act & Assert
        with pytest.raises(TypeError):
            VotingEventOperations.delete_voting_event(event_id, invalid_user_id)

        mock_session.execute.assert_called_once()
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()

    def test_concurrent_delete_voting_event(self, mock_session):
        # Arrange
        event_id = 1
        user_id = 1
        mock_session.execute.return_value = None
        mock_session.commit.return_value = None

        # Simulate concurrent deletion
        def side_effect(*args, **kwargs):
            if mock_session.execute.call_count == 1:
                return None
            raise IntegrityError(None, None, None)

        mock_session.execute.side_effect = side_effect

        # Act
        VotingEventOperations.delete_voting_event(event_id, user_id)
        with pytest.raises(IntegrityError):
            VotingEventOperations.delete_voting_event(event_id, user_id)

        # Assert
        assert mock_session.execute.call_count == 2
        assert mock_session.commit.call_count == 1
        assert mock_session.rollback.call_count == 1
        assert mock_session.close.call_count == 2

    def test_delete_voting_event_during_active_session(self, mock_session):
        # Arrange
        event_id = 1
        user_id = 2
        mock_session.execute.return_value = None
        mock_session.commit.return_value = None

        # Act
        VotingEventOperations.delete_voting_event(event_id, user_id)

        # Assert
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

        # Check if the correct update query was executed
        update_call = mock_session.execute.call_args[0][0]
        assert isinstance(update_call, update)
        assert update_call.table == VotingEvent.__table__
        assert update_call._values == {"is_deleted": True}
        assert str(update_call._where_criteria) == str(
            and_(VotingEvent.event_id == event_id, VotingEvent.created_by == user_id)
        )

    def test_delete_multiple_voting_events(self, mock_session):
        # Arrange
        event_ids = [1, 2, 3]
        user_id = 1
        mock_session.execute.return_value = None
        mock_session.commit.return_value = None

        # Act
        for event_id in event_ids:
            VotingEventOperations.delete_voting_event(event_id, user_id)

        # Assert
        assert mock_session.execute.call_count == len(event_ids)
        for event_id in event_ids:
            mock_session.execute.assert_any_call(
                update(VotingEvent)
                .values(is_deleted=True)
                .where(
                    and_(
                        VotingEvent.event_id == event_id,
                        VotingEvent.created_by == user_id,
                    )
                )
            )
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

    def test_delete_voting_event_with_associated_data(self, mock_session):
        # Arrange
        event_id = 1
        user_id = 1
        mock_session.execute.return_value = None
        mock_session.commit.return_value = None

        # Act
        VotingEventOperations.delete_voting_event(event_id, user_id)

        # Assert
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

        # Check if the correct update query was executed
        update_call = mock_session.execute.call_args[0][0]
        assert isinstance(update_call, Update)
        assert update_call.table == VotingEvent.__table__
        assert update_call._values == {"is_deleted": True}
        assert (
            str(update_call._where_criteria[0])
            == "voting_event.event_id = :event_id_1 AND voting_event.created_by = :created_by_1"
        )
