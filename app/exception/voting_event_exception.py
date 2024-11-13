""" Exception classes related to the votes stuff """
from app.exception.custom_exception import CustomException


class VotingEventDoesNotExists(CustomException):
    """ Exception raised when a vote doesn't exist """

    def __init__(self, message="Vote doesn't exists"):
        self.message = message
