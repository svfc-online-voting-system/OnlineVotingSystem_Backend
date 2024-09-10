from app import create_app
import dotenv
import os

dotenv.load_dotenv()

app = create_app()

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=os.getenv('FLASK_RUN_PORT', 5000), debug=os.getenv('FLASK_DEBUG', True))
