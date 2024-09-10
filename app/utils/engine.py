from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
import logging

file_handler = logging.FileHandler('authentication.logs')
file_handler.setLevel(logging.WARNING)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)

logger = logging.getLogger()
logger.setLevel(logging.WARNING)
logger.addHandler(file_handler)
logger.addHandler(console_handler)


DATABASE_URL = (
	f"{os.getenv('DATABASE_BASE_URL')}"
	f"{os.getenv('DATABASE_USER')}:"
	f"{os.getenv('DATABASE_PASSWORD')}@"
	f"{os.getenv('DATABASE_HOSTNAME')}:"
	f"{os.getenv('DATABASE_PORT')}/"
	f"{os.getenv('DATABASE_NAME')}"
)

engine = create_engine(DATABASE_URL)

session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_engine():
	return engine


def get_session():
	return session_local()


