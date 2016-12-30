import json
from flask import Blueprint
from flask import request
from api.internal.internal_server import InternalServer

# -- Global

history_api = Blueprint('history_api', __name__)


# Get the init db process status
@history_api.route('/v1/history/<path:image_name>', methods=['GET'])
def get_history_by_image_name(image_name):
    _id = request.args.get('id')
    history = InternalServer.get_mongodb_driver().get_docker_image_history(image_name, _id)
    if len(history) == 0:
        return json.dumps({'err': 404, 'msg': 'History not found'}, sort_keys=True), 404
    return json.dumps(history, sort_keys=True)
