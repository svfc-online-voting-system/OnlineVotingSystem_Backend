from custom_exception import CustomException


class UserNotFound(CustomException):
	def __init__(self, message="User not found."):
		self.message = message
		super().__init__(message)