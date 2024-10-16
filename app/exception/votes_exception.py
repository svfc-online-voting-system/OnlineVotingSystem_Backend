""" EXception classes related to the votes stuff """
from app.exception.custom_exception import CustomException


class VoteDoesNotExists(CustomException):
    def __init__(self, message = "Vote doesn't exists"):
        self.message = message
        