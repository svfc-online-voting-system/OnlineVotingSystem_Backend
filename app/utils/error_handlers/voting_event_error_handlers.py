""" This module contains voting event error handlers. """

from app.exception.voting_event_exception import VotingEventDoesNotExists
from app.utils.error_handlers.base_error_handler import handle_error


def handle_voting_event_does_not_exists(error):
    """This function handles voting event does not exist errors."""
    if isinstance(error, VotingEventDoesNotExists):
        return handle_error(
            error, 404, "voting_event_does_not_exists", "Voting event does not exist."
        )
    raise error
