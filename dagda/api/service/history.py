import json
from flask import Blueprint
from flask import request
from api.internal.internal_server import InternalServer

# -- Global

history_api = Blueprint('history_api', __name__)


# Get the history of an image analysis
@history_api.route('/v1/history', methods=['GET'])
def get_history():
    history = InternalServer.get_mongodb_driver().get_docker_image_all_history()
    if len(history) == 0:
        return json.dumps({'err': 404, 'msg': 'Analysis not found'}, sort_keys=True), 404
    return json.dumps(history, sort_keys=True)


# Get the history of an image analysis
@history_api.route('/v1/history/<path:image_name>', methods=['GET'])
def get_history_by_image_name(image_name):
    id = request.args.get('id')
    history = InternalServer.get_mongodb_driver().get_docker_image_history(image_name, id)
    if len(history) == 0:
        return json.dumps({'err': 404, 'msg': 'History not found'}, sort_keys=True), 404
    return json.dumps(history, sort_keys=True)
