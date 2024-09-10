import logging
import os
from flask import Flask
from flask_jwt_extended import JWTManager
from app.routes.auth import auth_blueprint


def create_app():
	app = Flask(__name__)
	
	app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default-secret-key')
	
	jwt = JWTManager(app)
	
	os.makedirs(os.path.join(app.root_path, 'logs'), exist_ok=True)
	
	# Set up logging (can be adjusted for production-level logging)
	logging.basicConfig(
		level=logging.INFO,
		format='%(asctime)s - %(levelname)s - %(message)s',
		handlers=[
			logging.FileHandler(os.path.join(app.root_path, 'logs', 'authentication.log')),
			logging.StreamHandler()
		]
	)
	
	app.register_blueprint(auth_blueprint)
	
	logger = logging.getLogger()
	
	return app
