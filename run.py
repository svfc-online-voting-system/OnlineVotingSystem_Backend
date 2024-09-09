from app import create_app
import dotenv
import os

dotenv.load_dotenv()

# Initialize the app using the factory function from app/__init__.py
app = create_app()

if __name__ == '__main__':
	# Set the app to run in development mode if not specified otherwise
	app.run(host='0.0.0.0', port=os.getenv('FLASK_RUN_PORT', 5000), debug=os.getenv('FLASK_DEBUG', True))
