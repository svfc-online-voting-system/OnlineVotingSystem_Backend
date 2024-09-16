"""
    Restful API for Online Voting System
"""

import dotenv
from flask_cors import CORS
from app import create_app

dotenv.load_dotenv()

app = create_app()
# CORS(
#     app=app,
#     cors_allowed_origins="http://localhost:4200",
#     supports_credentials=True,
#     resources={r"/app/": {"origins": "*"}}
# )
CORS(app, cors_allowed_origins="*", supports_credentials=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
