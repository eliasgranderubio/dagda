import json
import datetime
from flask import Blueprint
from api.internal.internal_server import InternalServer


# -- Global

monitor_api = Blueprint('monitor_api', __name__)


# Starts monitor by container id
@monitor_api.route('/v1/monitor/containers/<string:container_id>/start', methods=['POST'])
def start_monitor_by_container_id(container_id):
    # -- Checks input
    if not container_id:
        return json.dumps({'err': 400, 'msg': 'Bad container id'}, sort_keys=True), 400

    # -- Retrieves docker image name
    try:
        image_name = InternalServer.get_docker_driver().get_docker_image_name_from_container_id(container_id)
    except:
        return json.dumps({'err': 404, 'msg': 'Container Id not found'}, sort_keys=True), 404

    # -- Checks if the container is already being monitoring
    if InternalServer.get_mongodb_driver().is_there_a_started_monitoring(container_id):
        return json.dumps({'err': 400, 'msg': 'The monitoring for the requested container id is already started'},
                          sort_keys=True), 400

    now = datetime.datetime.now().timestamp()
    # -- Create image_history
    history = {}
    history['image_name'] = image_name
    history['timestamp'] = now
    history['status'] = 'Monitoring'
    history['runtime_analysis'] = {'container_id': container_id,
                                   'start_timestamp': now,
                                   'stop_timestamp': None,
                                   'anomalous_activities_detected': None}
    id = InternalServer.get_mongodb_driver().insert_docker_image_scan_result_to_history(history)

    # -- Return
    output = {}
    output['id'] = str(id)
    output['image_name'] = image_name
    output['msg'] = 'Monitoring of docker container with id <' + container_id + '> started'
    return json.dumps(output, sort_keys=True), 202


# Stop monitor by container id
@monitor_api.route('/v1/monitor/containers/<string:container_id>/stop', methods=['POST'])
def stop_monitor_by_container_id(container_id):
    # -- Checks input
    if not container_id:
        return json.dumps({'err': 400, 'msg': 'Bad container id'}, sort_keys=True), 400

    # -- Retrieves docker image name
    try:
        image_name = InternalServer.get_docker_driver().get_docker_image_name_from_container_id(container_id)
    except:
        return json.dumps({'err': 404, 'msg': 'Container Id not found'}, sort_keys=True), 404

    # -- Checks if the container is already being monitoring
    if not InternalServer.get_mongodb_driver().is_there_a_started_monitoring(container_id):
        return json.dumps({'err': 400, 'msg': 'There is not monitoring for the requested container id'},
                          sort_keys=True), 400

    now = datetime.datetime.now().timestamp()
    # -- Process request
    InternalServer.get_mongodb_driver().update_runtime_monitoring_analysis(container_id)
    monitoring_result = InternalServer.get_mongodb_driver().get_a_started_monitoring(container_id)
    monitoring_result['runtime_analysis']['stop_timestamp'] = now
    monitoring_result['status'] = 'Completed'
    id = str(monitoring_result['_id'])

    # -- Update history
    InternalServer.get_mongodb_driver().update_docker_image_scan_result_to_history(id, monitoring_result)

    # -- Return
    return json.dumps(InternalServer.get_mongodb_driver().get_docker_image_history(image_name, id)[0], sort_keys=True)
