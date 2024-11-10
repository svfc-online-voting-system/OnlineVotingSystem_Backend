"""Development configuration."""

from os import getenv
from datetime import timedelta

from app.config.base_config import BaseConfig


class DevelopmentConfig(BaseConfig):  # pylint: disable=R0903
    """Development configuration."""

    DEBUG = True
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=60)
    MAIL_USERNAME = getenv("MAIL_USERNAME")
