""" Exception classes related to the votes stuff """
from app.exception.custom_exception import CustomException


class VoteDoesNotExists(CustomException):
    """ Exception raised when a vote doesn't exists """

    def __init__(self, message="Vote doesn't exists"):
        self.message = message
