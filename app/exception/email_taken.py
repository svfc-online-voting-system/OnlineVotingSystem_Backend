from app.exception.custom_exception import CustomException


class EmailAlreadyTaken(CustomException):
	"""This is for error that will be raised when the user creates an account with an email that is already taken. A
	bit redundant, but it will be beneficial for custom errors rather than SQL Generic Errors on Primary keys.
	Additionally, this approach will ultimately lay off the exception on the API Level, further reducing the load for
	database."""
	def __init__(self, message="Email already taken."):
		self.message = message
		super().__init__(message)
