from app.exception.custom_exception import CustomException


class RegistrationError(CustomException):
	"""This is the defined error if the registration went south."""
	def __init__(self, message="Registration error."):
		self.message = message
		super().__init__(self.message)
	