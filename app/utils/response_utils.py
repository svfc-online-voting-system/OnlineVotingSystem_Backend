""" This is the modularize set response function that can be use anywhere inside the project """
from os import getenv
from datetime import datetime, timedelta
from flask import make_response, jsonify, json

ENVIRONMENT = getenv('ENVIRONMENT', 'development')
is_production = ENVIRONMENT == 'production'

def set_response(status_code, messages, **kwargs):
    """ This function sets the response for the routes. """
    response = make_response(jsonify(messages), status_code)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Date'] = f"{datetime.now()}"
    origin = getenv('LOCAL_FRONTEND_URL') if not is_production else getenv('LIVE_FRONTEND_URL')
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS, GET, DELETE, PUT'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    if 'authorization_token' in kwargs:
        response.set_cookie(
            key='Authorization',
            value=kwargs['authorization_token'],
            httponly=True,
            secure=True,
            samesite='None',
            expires=datetime.now() + timedelta(days=365),
            path='/'
        )
    if 'csrf_token' in kwargs:
        response.set_cookie(
            key='X-CSRF-TOKEN',
            value=kwargs['csrf_token'],
            httponly=True,
            secure=True,
            samesite='None',
            path='/'
        )
    response_data = json.dumps(messages)
    response.data = response_data
    response.status_code = status_code
    response.headers["Content-Length"] = str(len(response_data))
    return response