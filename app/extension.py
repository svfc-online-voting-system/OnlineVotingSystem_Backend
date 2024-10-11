""" Flask extensions are created here. This is to prevent circular imports. """
from flask_mail import Mail
from flask_wtf import CSRFProtect

mail = Mail()
csrf = CSRFProtect()
