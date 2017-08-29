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

import docker
from docker.errors import DockerException
from docker.errors import NotFound
from log.dagda_logger import DagdaLogger
from exception.dagda_error import DagdaError


class DockerDriver:

    # -- Public methods

    # DockerDriver Constructor
    def __init__(self):
        super(DockerDriver, self).__init__()
        try:
            # Return a client configured from environment variables. The environment variables used are the same as
            # those used by the Docker command-line client.
            self.cli = docker.from_env(version="auto", timeout=3600).api
        except DockerException:
            DagdaLogger.get_logger().error('Error while fetching Docker server API version: Assumming Travis CI tests.')
            self.cli = None

    # Gets the docker image name from a running container
    def get_docker_image_name_by_container_id(self, container_id):
        containers = self.cli.containers(filters={'id': container_id})
        return containers[0]['Image']

    # Gets the docker container ids from image name
    def get_docker_container_ids_by_image_name(self, image_name):
        ids = []
        try:
            containers = self.cli.containers()
            for c in containers:
                if c['Image'] == image_name:
                    ids = c['Id']
        except NotFound:
            # Nothing to do
            pass
        return ids

    # Checks if docker image is in the local machine
    def is_docker_image(self, image_name):
        image = self.cli.images(name=image_name)
        return len(image) > 0

    # Executes docker exec command and return the output
    def docker_exec(self, container_id, cmd, show_stdout, show_stderr):
        dict = self.cli.exec_create(container=container_id, cmd=cmd, stdout=show_stdout, stderr=show_stderr)
        return (self.cli.exec_start(exec_id=dict.get('Id'))).decode("utf-8", errors="ignore")

    # Gets logs from docker container
    def docker_logs(self, container_id, show_stdout, show_stderr, follow):
        try:
            return (self.cli.logs(container=container_id, stdout=show_stdout, stderr=show_stderr, follow=follow))\
                   .decode('utf-8')
        except docker.errors.APIError as ex:
            if "configured logging reader does not support reading" in str(ex):
                message = "Docker logging driver is not set to be 'json-file' or 'journald'"
                DagdaLogger.get_logger().error(message)
                raise DagdaError(message)
            else:
                message = "Unexpected exception of type {0} occured: {1!r}" \
                    .format(type(ex).__name__, str(ex))
                DagdaLogger.get_logger().error(message)
                raise ex

    # Creates container and return the container id
    def create_container(self, image_name, entrypoint=None, volumes=None, host_config=None):
        container = self.cli.create_container(image=image_name, entrypoint=entrypoint, volumes=volumes,
                                              host_config=host_config)
        return container.get('Id')

    # Docker pull
    def docker_pull(self, image_name):
        return self.cli.pull(image_name, tag='latest')

    # Removes the docker image
    def docker_remove_image(self, image_name):
        self.cli.remove_image(image=image_name, force=True)

    # Removes docker container
    def docker_remove_container(self, container_id):
        self.cli.remove_container(container=container_id, force=True)

    # Start container
    def docker_start(self, container_id):
        self.cli.start(container=container_id)

    # Stop container
    def docker_stop(self, container_id):
        self.cli.stop(container=container_id)

    # Gets docker client
    def get_docker_client(self):
        return self.cli
