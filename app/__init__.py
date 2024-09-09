import logging
import os
from flask import Flask


def create_app():
	app = Flask(__name__)
	
	# Create logs directory if it doesn't exist
	os.makedirs(os.path.join(app.root_path, 'logs'), exist_ok=True)
	
	# Set up logging
	logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[ logging.FileHandler(os.path.join(app.root_path, 'logs', 'authentication.log')), logging.StreamHandler()])
	
	logger = logging.getLogger()
	
	return app
