from flask import Flask
import dotenv
import os
from flask_jwt_extended import JWTManager

dotenv.load_dotenv()

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
jwt = JWTManager(app)


@app.route('/')
def hello_world():  # put application's code here
	return 'Hello World!'


if __name__ == '__main__':
	app.run()
