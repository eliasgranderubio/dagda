#
# Licensed to Dagda under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Dagda licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

import datetime
from flask import Blueprint
from flask import jsonify
from api.internal.internal_server import InternalServer


# -- Global

monitor_api = Blueprint('monitor_api', __name__)


# Starts monitor by container id
@monitor_api.route('/v1/monitor/containers/<string:container_id>/start', methods=['POST'])
def start_monitor_by_container_id(container_id):
    # -- Check runtime monitor status
    if not InternalServer.is_runtime_analysis_enabled():
        return jsonify({'err': 503, 'msg': 'Behaviour analysis service unavailable'}), 503

    # -- Checks input
    if not container_id:
        return jsonify({'err': 400, 'msg': 'Bad container id'}), 400

    # -- Retrieves docker image name
    try:
        image_name = InternalServer.get_docker_driver().get_docker_image_name_by_container_id(container_id)
    except:
        return jsonify({'err': 404, 'msg': 'Container Id not found'}), 404

    # -- Checks if the container is already being monitoring
    if InternalServer.get_mongodb_driver().is_there_a_started_monitoring(container_id):
        return jsonify({'err': 400, 'msg': 'The monitoring for the requested container id is already started'}), 400

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
    return jsonify(output), 202


# Stop monitor by container id
@monitor_api.route('/v1/monitor/containers/<string:container_id>/stop', methods=['POST'])
def stop_monitor_by_container_id(container_id):
    # -- Check runtime monitor status
    if not InternalServer.is_runtime_analysis_enabled():
        return jsonify({'err': 503, 'msg': 'Behaviour analysis service unavailable'}), 503

    # -- Checks input
    if not container_id:
        return jsonify({'err': 400, 'msg': 'Bad container id'}), 400

    # -- Retrieves docker image name
    try:
        image_name = InternalServer.get_docker_driver().get_docker_image_name_by_container_id(container_id)
    except:
        return jsonify({'err': 404, 'msg': 'Container Id not found'}), 404

    # -- Checks if the container is already being monitoring
    if not InternalServer.get_mongodb_driver().is_there_a_started_monitoring(container_id):
        return jsonify({'err': 400, 'msg': 'There is not monitoring for the requested container id'}), 400

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
    return jsonify(InternalServer.get_mongodb_driver().get_docker_image_history(image_name, id)[0])
