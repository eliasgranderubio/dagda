import json
import datetime
from flask import Blueprint
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


# -- Util methods

def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'K', 'M', 'G']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Y', suffix)
