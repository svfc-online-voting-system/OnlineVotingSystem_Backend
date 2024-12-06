""" This is the modularize set response function that can be use anywhere inside the project """

from datetime import datetime
from flask import make_response, jsonify, json


def set_response(status_code, messages):
    """This function sets the response for the routes."""
    response = make_response(jsonify(messages), status_code)
    response.headers["Content-Type"] = "application/json"
    response.headers["Date"] = f"{datetime.now()}"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS, GET, DELETE, PUT"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response_data = json.dumps(messages)
    response.data = response_data
    response.status_code = status_code
    response.headers["Content-Length"] = str(len(response_data))
    return response
