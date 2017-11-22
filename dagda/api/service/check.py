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
from exception.dagda_error import DagdaError
from log.dagda_logger import DagdaLogger
from api.internal.internal_server import InternalServer

# -- Global

check_api = Blueprint('check_api', __name__)


# Check docker by image name
@check_api.route('/v1/check/images/<path:image_name>', methods=['POST'])
def check_docker_by_image_name(image_name):
    # -- Check input
    if not image_name:
        return jsonify({'err': 400, 'msg': 'Bad image name'}), 400

    # -- Docker pull from remote registry if it is necessary
    try:
        pulled = False
        if not InternalServer.get_docker_driver().is_docker_image(image_name):
            output = InternalServer.get_docker_driver().docker_pull(image_name)
            if 'errorDetail' in output:
                msg = 'Error: image library/'+ image_name + ':latest not found'
                DagdaLogger.get_logger().error(msg)
                raise DagdaError(msg)
            pulled = True
    except:
        return jsonify({'err': 404, 'msg': 'Image name not found'}), 404

    # -- Process request
    data = {}
    data['image_name'] = image_name
    data['timestamp'] = datetime.datetime.now().timestamp()
    data['status'] = 'Analyzing'
    id = InternalServer.get_mongodb_driver().insert_docker_image_scan_result_to_history(data)
    InternalServer.get_dagda_edn().put({'msg': 'check_image', 'image_name': image_name, '_id': str(id),
                                        'pulled': pulled})

    # -- Return
    output = {}
    output['id'] = str(id)
    output['msg'] = 'Accepted the analysis of <' + image_name + '>'
    return jsonify(output), 202


# Check docker by container id
@check_api.route('/v1/check/containers/<string:container_id>', methods=['POST'])
def check_docker_by_container_id(container_id):
    # -- Check input
    if not container_id:
        return jsonify({'err': 400, 'msg': 'Bad container id'}), 400

    # -- Retrieves docker image name
    try:
        image_name = InternalServer.get_docker_driver().get_docker_image_name_by_container_id(container_id)
    except:
        return jsonify({'err': 404, 'msg': 'Container Id not found'}), 404

    # -- Process request
    data = {}
    data['image_name'] = image_name
    data['timestamp'] = datetime.datetime.now().timestamp()
    data['status'] = 'Analyzing'
    id = InternalServer.get_mongodb_driver().insert_docker_image_scan_result_to_history(data)
    InternalServer.get_dagda_edn().put({'msg': 'check_container', 'container_id': container_id, '_id': str(id)})

    # -- Return
    output = {}
    output['id'] = str(id)
    output['msg'] = 'Accepted the analysis of <' + image_name + '> with id: ' + container_id
    return jsonify(output), 202
