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
import os
import shutil
import tempfile
from tarfile import TarFile
from tarfile import ReadError
from api.internal.internal_server import InternalServer
from log.dagda_logger import DagdaLogger


# Prepare filesystem bundle
def extract_filesystem_bundle(docker_driver, container_id=None, image_name=None):
    temporary_dir = tempfile.mkdtemp()
    # Get and save filesystem bundle
    if container_id is not None:
        data = docker_driver.get_docker_client().export(container=container_id).data
        name = container_id
    else:
        data = docker_driver.get_docker_client().get_image(image=image_name).data
        name = image_name.replace('/', '_').replace(':', '_')
    with open(temporary_dir + "/" + name + ".tar", "wb") as file:
        file.write(data)
    # Untar filesystem bundle
    tarfile = TarFile(temporary_dir + "/" + name + ".tar")
    tarfile.extractall(temporary_dir)
    os.remove(temporary_dir + "/" + name + ".tar")
    if image_name is not None:
        layers = _get_layers_from_manifest(temporary_dir)
        _untar_layers(temporary_dir, layers)
    # Return
    return temporary_dir


# Clean the temporary directory
def clean_up(temporary_dir):
    shutil.rmtree(temporary_dir)


# -- Private methods

# Gets docker image layers from manifest
def _get_layers_from_manifest(dir):
    layers = []
    with open(dir + "/manifest.json", "r") as manifest_json:
        json_info = json.loads(''.join(manifest_json.readlines()))
        if len(json_info) == 1 and 'Layers' in json_info[0]:
            for layer in json_info[0]['Layers']:
                layers.append(layer)
    return layers


# Untar docker image layers
def _untar_layers(dir, layers):
    output = {}
    # Untar layer filesystem bundle
    for layer in layers:
        tarfile = TarFile(dir + "/" + layer)
        for member in tarfile.getmembers():
            output[member.name] = member
    for member_name in output:
        try:
            tarfile.extract(output[member_name], path=dir, set_attrs=False)
        except (ValueError, ReadError) as ex:
            if InternalServer.is_debug_logging_enabled():
                message = "Unexpected exception of type {0} occured while untaring the docker image: {1!r}" \
                    .format(type(ex).__name__, ex.get_message() if type(ex).__name__ == 'DagdaError' else ex.args)
                DagdaLogger.get_logger().debug(message)
        except PermissionError as ex:
            message = "Unexpected error occured while untaring the docker image: " + \
                      "Operation not permitted on {0!r}".format(member_name)
            DagdaLogger.get_logger().warn(message)

    # Clean up
    for layer in layers:
        clean_up(dir + "/" + layer[:-10])
