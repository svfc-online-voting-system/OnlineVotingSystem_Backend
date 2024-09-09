from app.exception.custom_exception import CustomException


class RequiredError(CustomException):
	"""This error is responsible for raising an exception that occurs when field that is required isn't filled with
	correct data"""
	def __init__(self, message="A field(s) that are required doesn't have data"):
		self.message = message
		super().__init__(message)
