""" Flask extensions are created here. This is to prevent circular imports. """
from flask_mail import Mail
from flask_smorest import Api

mail = Mail()
api = Api()
