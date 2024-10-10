"""
    This is responsible for initializing the Database engine and session
"""
from os import getenv
import logging
from logging import FileHandler, StreamHandler, getLogger
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

file_handler = FileHandler('authentication.logs')
file_handler.setLevel(logging.WARNING)

console_handler = StreamHandler()
console_handler.setLevel(logging.WARNING)

logger = getLogger()
logger.setLevel(logging.WARNING)
logger.addHandler(file_handler)
logger.addHandler(console_handler)


DATABASE_URL = (
    f"{getenv('DATABASE_BASE_URL')}"
    f"{getenv('DATABASE_USERNAME')}:"
    f"{getenv('DATABASE_PASSWORD')}@"
    f"{getenv('DATABASE_HOSTNAME')}:"
    f"{getenv('DATABASE_PORT')}/"
    f"{getenv('DATABASE_NAME')}"
)

engine = create_engine(DATABASE_URL)

session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_engine():
    """ Return the engine """
    return engine


def get_session():
    """ Returns the session """
    return session_local()
