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

docker_api = Blueprint('docker_api', __name__)


# Gets all docker images info
@docker_api.route('/v1/docker/images', methods=['GET'])
def get_all_docker_images():
    images = InternalServer.get_docker_driver().get_docker_client().images()
    output = []
    for image in images:
        i = {}
        if image['RepoTags'] is None:
            i['tags'] = list(['None:None'])
        else:
            i['tags'] = list(set(image['RepoTags']))
        i['id'] = image['Id'][7:][:12]
        i['created'] = str(datetime.datetime.utcfromtimestamp(image['Created']))
        i['size'] = sizeof_fmt(image['VirtualSize'])
        output.append(i)
    return jsonify(output)


# Gets all running containers info
@docker_api.route('/v1/docker/containers', methods=['GET'])
def get_all_running_containers():
    containers = InternalServer.get_docker_driver().get_docker_client().containers()
    output = []
    for container in containers:
        c = {}
        c['id'] = container['Id'][:12]
        c['image'] = container['Image']
        c['created'] = str(datetime.datetime.utcfromtimestamp(container['Created']))
        c['status'] = container['State']
        c['name'] = container['Names'][0][1:]
        output.append(c)
    return jsonify(output)


# -- Util methods

def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'K', 'M', 'G']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Y', suffix)
