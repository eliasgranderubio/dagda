import json
import datetime
from flask import Blueprint
from api.internal.internal_server import InternalServer

# -- Global

check_api = Blueprint('check_api', __name__)


# Check docker by image name
@check_api.route('/v1/check/images/<path:image_name>', methods=['POST'])
def check_docker_by_image_name(image_name):
    # -- Check input
    if not image_name:
        return json.dumps({'err': 400, 'msg': 'Bad image name'}, sort_keys=True), 400

    # -- Docker pull from remote registry if it is necessary
    try:
        pulled = False
        if not InternalServer.get_docker_driver().is_docker_image(image_name):
            InternalServer.get_docker_driver().docker_pull(image_name)
            pulled = True
    except:
        return json.dumps({'err': 404, 'msg': 'Image name not found'}, sort_keys=True), 404

    # -- Process request
    data = {}
    data['image_name'] = image_name
    data['timestamp'] = datetime.datetime.now().timestamp()
    data['status'] = 'Analyzing'
    _id = InternalServer.get_mongodb_driver().insert_docker_image_scan_result_to_history(data)
    InternalServer.get_dagda_edn().put({'msg': 'check_image', 'image_name': image_name, '_id': str(_id),
                                        'pulled': pulled})

    # -- Return
    output = {}
    output['id'] = str(_id)
    output['msg'] = 'Accepted the analysis of <' + image_name + '>'
    return json.dumps(output, sort_keys=True), 202


# Check docker by container id
@check_api.route('/v1/check/containers/<string:container_id>', methods=['POST'])
def check_docker_by_container_id(container_id):
    # -- Check input
    if not container_id:
        return json.dumps({'err': 400, 'msg': 'Bad container id'}, sort_keys=True), 400

    # -- Retrieves docker image name
    try:
        image_name = InternalServer.get_docker_driver().get_docker_image_name_from_container_id(container_id)
    except:
        return json.dumps({'err': 404, 'msg': 'Container Id not found'}, sort_keys=True), 404

    # -- Process request
    data = {}
    data['image_name'] = image_name
    data['timestamp'] = datetime.datetime.now().timestamp()
    data['status'] = 'Analyzing'
    _id = InternalServer.get_mongodb_driver().insert_docker_image_scan_result_to_history(data)
    InternalServer.get_dagda_edn().put({'msg': 'check_container', 'container_id': container_id, '_id': str(_id)})

    # -- Return
    output = {}
    output['id'] = str(_id)
    output['msg'] = 'Accepted the analysis of <' + image_name + '> with id: ' + container_id
    return json.dumps(output, sort_keys=True), 202