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

import json
import datetime
from flask import Blueprint
from flask import request
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
    return json.dumps(output, sort_keys=True)


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
    return json.dumps(output, sort_keys=True)


# Gets docker daemon events
@docker_api.route('/v1/docker/events', methods=['GET'])
def get_docker_daemon_events():
    # Init
    event_from = request.args.get('event_from')
    if not event_from:
        event_from = None
    event_type = request.args.get('event_type')
    if not event_type:
        event_type = None
    event_action = request.args.get('event_action')
    if not event_action:
        event_action = None
    # Run query
    events = InternalServer.get_mongodb_driver().get_docker_events_daemon(op_from=event_from,
                                                                          op_type=event_type,
                                                                          op_action=event_action)
    # Return
    if len(events) == 0:
        return json.dumps({'err': 404, 'msg': 'Docker daemon events not found'}, sort_keys=True), 404
    return json.dumps(events, sort_keys=True)


# -- Util methods

def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'K', 'M', 'G']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Y', suffix)
