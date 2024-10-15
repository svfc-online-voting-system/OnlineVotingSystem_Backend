""" This is the modularize set response function that can be use anywhere inside the project """
from os import getenv
from datetime import datetime, timedelta
from flask import make_response, jsonify, json

ENVIRONMENT = getenv('ENVIRONMENT', 'development')
is_production = ENVIRONMENT == 'production'

def set_response(status_code, messages, **kwargs):
    """ This function sets the response for the routes. """
    path: str = ''
    response = make_response(jsonify(messages), status_code)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Date'] = f"{datetime.now()}"
    origin = getenv('LOCAL_FRONTEND_URL') if not is_production else getenv('LIVE_FRONTEND_URL')
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS, GET, DELETE, PUT'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    # TODO: To be implemented later or in the future
    # if 'role' in kwargs:
    #     if kwargs['role'] == 'admin':
    #         path = '/admin'
    #     else:
    #         path = '/user'
    # CodeQL false positive: py/insecure-cookie
    # We are intentionally setting SameSite=None to allow cross-origin requests.
    # This is necessary for our application architecture where the frontend and backend
    # are on different domains. We mitigate the security risks by:
    # 1. Setting secure=True to ensure cookies are only sent over HTTPS
    # 2. Setting httponly=True to prevent JavaScript access to the cookie
    # 3. Implementing proper CORS configuration and additional server-side checks
    cookie_options = {
        'httponly': True,
        'secure': True,
        'samesite': 'None',
        # 'path': path,
        'path': '/'
    }
    if 'authorization_token' in kwargs:
        response.set_cookie(
            key='Authorization',
            value=kwargs['authorization_token'],
            expires=datetime.now() + timedelta(days=365),
            **cookie_options
        )
    if 'csrf_token' in kwargs:
        response.set_cookie(
            key='X-CSRFToken',
            value=kwargs['csrf_token'],
            **cookie_options
        )
    response_data = json.dumps(messages)
    response.data = response_data
    response.status_code = status_code
    response.headers["Content-Length"] = str(len(response_data))
    return response
