"""Testing configuration."""

from datetime import timedelta
from os import getenv

from app.config.base_config import BaseConfig


class TestingConfig(BaseConfig):  # pylint: disable=R0903
    """Testing configuration."""

    TESTING = True
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    MAIL_USERNAME = getenv("MAIL_USERNAME")
