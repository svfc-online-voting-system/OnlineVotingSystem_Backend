""" This module contains the email utility functions. """
from flask_mail import Message
from app.extension import mail

def send_mail(email: str, message: str, subject: str):
    """ This function sends an email. """
    msg = Message(
        subject=subject,
        recipients=[email],
    )
    msg.html = message
    mail.send(msg)
