""" Flask extensions are created here. This is to prevent circular imports. """
from flask_mail import Mail
from flask_seasurf import SeaSurf

mail = Mail()
csrf = SeaSurf()