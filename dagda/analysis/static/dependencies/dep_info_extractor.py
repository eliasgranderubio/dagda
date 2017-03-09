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
from exception.dagda_error import DagdaError


# Gets programming languages dependencies from docker image
def get_dependencies_from_docker_image(docker_driver, image_name):
    # Docker pull for ensuring the deepfenceio/deepfence_depcheck image
    docker_driver.docker_pull('deepfenceio/deepfence_depcheck')
    # Start container
    container_id = docker_driver.create_container('deepfenceio/deepfence_depcheck',
                                                  "bash -c '/usr/local/bin/start_services.sh -t all -i " + image_name +
                                                  " -j true; sleep 5'",
                                                  [
                                                         '/var/run/docker.sock',
                                                         '/fenced/mnt/host/var/lib/docker/',
                                                         '/fenced/mnt/host/',
                                                         '/tmp'
                                                  ],
                                                  docker_driver.get_docker_client().create_host_config(
                                                          binds=[
                                                                '/var/run/docker.sock:/var/run/docker.sock',
                                                                '/var/lib/docker/:/fenced/mnt/host/var/lib/docker/:rw',
                                                                '/:/fenced/mnt/host/:ro',
                                                                '/tmp:/tmp:rw'
                                                                ]))
    docker_driver.docker_start(container_id)
    # Wait for depcheck
    docker_driver.docker_logs(container_id, True, False, True)
    # Get dependencies info
    dependencies_info = raw_info_to_json_array(read_depcheck_output_file(image_name))
    # Stop container
    docker_driver.docker_stop(container_id)
    # Return
    return get_filtered_dependencies_info(dependencies_info)


# Filters the raw info and converts it to json
def raw_info_to_json_array(raw_info):
    without_colours = raw_info.replace("\033[1;33m", '').replace("\033[1;39m", '') \
                                .replace("\033[0;32m", '').replace("\033[34;1m", '') \
                                .replace("\033[34m", '').replace("\033[0m", '')
    tmp = without_colours.replace("[INFO] Cleaning up", '').replace("[INFO] Done", '') \
                         .replace("\r", '').replace("\n", '')
    if "{" in tmp:
        deleted_debug_info = "[" + (tmp[tmp.index('{'):]).replace("}", "},")
        deleted_debug_info = deleted_debug_info[:len(deleted_debug_info)-1] + "]"
    else:
        deleted_debug_info = "[]"
    return json.loads(deleted_debug_info)


# Gets filtered dependencies info
def get_filtered_dependencies_info(dependencies):
    output_set = set()
    for dependency in dependencies:
        if "cpe" in dependency["cve_caused_by_package"]:
            splitted_package = dependency["cve_caused_by_package"].split(":")
            if len(splitted_package) > 4:
                data = dependency['cve_type'] + "#" + splitted_package[3] + "#" + splitted_package[4]
                if data not in output_set:
                    output_set.add(data)
    return list(output_set)


# Reads the depcheck output file
def read_depcheck_output_file(image_name):
    image_name = image_name.replace("/", '_')
    filename = '/tmp/depcheck/' + image_name

    # Check file
    if not os.path.isfile(filename):
        raise DagdaError('Depcheck output file [' + filename + '] not found.')

    # Read file
    with open(filename, 'rb') as f:
        lines = f.readlines()
        raw_data = ''
        for line in lines:
            raw_data += line.decode('utf-8')

    # Return
    return raw_data
