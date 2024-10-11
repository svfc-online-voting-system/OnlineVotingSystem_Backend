"""
Factory function to create the Flask app instance.

	- Creates a Flask app instance.
	- Configures JWTManager for the app.
	- Sets up logging for the app.
	- Registers the auth blueprint.

Returns:
	Flask: The Flask app instance.
"""


from os import getenv, makedirs, path

from flask import Flask
from flask_jwt_extended import JWTManager
# app/__init__.py
from logging import FileHandler, StreamHandler, basicConfig, getLogger, INFO

from app.extension import mail, csrf
from app.routes.auth import auth_blueprint


def create_app():
    """Factory function to create the Flask app instance."""
    app = Flask(__name__, template_folder='templates')
    app.config['JWT_SECRET_KEY'] = getenv('JWT_SECRET_KEY')
    app.config['WTF_CSRF_SECRET_KEY'] = getenv('WTF_CSRF_SECRET_KEY')
    app.config['JWT_ACCESS_COOKIE_NAME'] = 'Authorization'
    app.config['WTF_CSRF_ENABLED'] = True
    JWTManager(app)
    csrf.init_app(app)
    app.config['MAIL_SERVER'] = getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = getenv('MAIL_PORT')
    app.config['MAIL_USE_TLS'] = getenv('MAIL_USE_TLS')
    app.config['MAIL_USERNAME'] = getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = getenv('MAIL_DEFAULT_SENDER')
    mail.init_app(app)
    makedirs(path.join(app.root_path, 'logs'), exist_ok=True)
    basicConfig(
        level=INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            FileHandler(path.join(app.root_path, 'logs', 'authentication.log')),
            StreamHandler()
        ]
    )
    app.register_blueprint(auth_blueprint)
    getLogger()
    return app
