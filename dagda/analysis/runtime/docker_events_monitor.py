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
import requests


# Docker daemon events monitor class

class DockerDaemonEventsMonitor:

    # -- Public methods

    # DockerDaemonEventsMonitor Constructor
    def __init__(self, docker_driver, mongodb_driver):
        super(DockerDaemonEventsMonitor, self).__init__()
        self.mongodb_driver = mongodb_driver
        self.docker_driver = docker_driver

    # Runs DockerDaemonEventsMonitor
    def run(self):
        # Read docker daemon events
        while True:
            try:
                for event in self.docker_driver.docker_events():
                    e = json.loads(event.decode('UTF-8').replace("\n", ""))
                    # Bulk insert
                    self.mongodb_driver.bulk_insert_docker_daemon_events([e])
            except requests.packages.urllib3.exceptions.ReadTimeoutError:
                # Nothing to do
                pass
