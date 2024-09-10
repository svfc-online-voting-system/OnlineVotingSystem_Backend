from app.exception.custom_exception import CustomException


class EmailNotFound(CustomException):
	"""This error is for error that the user tries to log in with an email that doesn't exist on the database."""
	def __init__(self, message="Email not found."):
		self.message = message
		super().__init__(message)
