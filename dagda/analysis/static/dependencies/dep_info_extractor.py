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
import tempfile
from exception.dagda_error import DagdaError


# Gets programming languages dependencies from docker image
def get_dependencies_from_docker_image(docker_driver, image_name, temp_dir):
    # Init
    filtered_image_name = image_name.replace(' ', '_').replace('/', '_').replace(':', '_')
    # Docker pull for ensuring the 3grander/4depcheck image
    docker_driver.docker_pull('3grander/4depcheck', '0.1.0')
    # Start container
    container_id = docker_driver.create_container('3grander/4depcheck:0.1.0',
                                                  'python3 /opt/app/4depcheck.py ' + filtered_image_name + ' ' +
                                                   temp_dir,
                                                  [
                                                         temp_dir,
                                                         tempfile.gettempdir() + '/4depcheck'
                                                         # The previous directory should be resolved as /tmp/4depcheck
                                                  ],
                                                  docker_driver.get_docker_client().create_host_config(
                                                    binds=[
                                                        temp_dir + ':' + temp_dir + ':ro',
                                                        tempfile.gettempdir() + '/4depcheck' + ':' +
                                                                tempfile.gettempdir() + '/4depcheck' + ':rw'
                                                  ]))
    docker_driver.docker_start(container_id)
    # Wait for 3grander/4depcheck
    docker_driver.docker_logs(container_id, True, False, True)
    # Get dependencies info
    dependencies_info = json.loads(read_4depcheck_output_file(filtered_image_name))
    # Stop container
    docker_driver.docker_stop(container_id)
    # Clean up
    docker_driver.docker_remove_container(container_id)
    # Return
    return get_filtered_dependencies_info(dependencies_info, temp_dir)


# Gets filtered dependencies info
def get_filtered_dependencies_info(dependencies, temp_dir):
    output_set = set()
    for dependency in dependencies:
        data = dependency['cve_type'] + "#" + dependency['cve_product'] + "#" + \
               dependency['cve_product_version'] + '#' + dependency['cve_product_file_path'].replace(temp_dir, '')
        if data not in output_set:
            output_set.add(data)
    return list(output_set)


# Reads the 4depcheck output file
def read_4depcheck_output_file(image_name):
    filename = tempfile.gettempdir() + '/4depcheck/' + image_name + '.json'

    # Check file
    if not os.path.isfile(filename):
        raise DagdaError('4depcheck output file [' + filename + '] not found.')

    # Read file
    with open(filename, 'rb') as f:
        lines = f.readlines()
        raw_data = ''
        for line in lines:
            raw_data += line.decode('utf-8')

    # Return
    return raw_data
