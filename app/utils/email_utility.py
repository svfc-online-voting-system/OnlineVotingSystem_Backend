""" This module contains the email utility functions. """
from flask_mail import Message, FlaskMailUnicodeDecodeError, BadHeaderError
from app.exception.required_error import RequiredError
from app.extension import mail

def send_mail(email: str, message: str, subject: str) -> str:
    """ This function sends an email. """
    try:
        msg = Message(
            subject=subject,
            recipients=[email],
            body=message
        )
        mail.send(msg)
        return 'sent_successfully'
    except (FlaskMailUnicodeDecodeError, BadHeaderError):
        return 'failed_to_send'
    except RequiredError:
        return 'required_error'
