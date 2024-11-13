""" Set up the logger for the application. """

from logging import INFO, Formatter
from logging.handlers import RotatingFileHandler
from os import path, makedirs

from flask import Flask


def setup_logging(app: Flask):  # pylint: disable=C0116
    log_dir = path.join(app.root_path, "logs")
    makedirs(log_dir, exist_ok=True)
    file_handler = RotatingFileHandler(
        path.join(log_dir, "app.log"), maxBytes=100000, backupCount=3
    )
    file_handler.setLevel(INFO)
    file_handler.setFormatter(Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    app.logger.addHandler(file_handler)
    app.logger.setLevel(INFO)
