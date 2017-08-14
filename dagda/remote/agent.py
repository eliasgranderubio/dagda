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

from analysis.analyzer import Analyzer


# Dagda remote agent class

class Agent:

    # -- Public methods

    # Agent Constructor
    def __init__(self, dagda_server_url):
        super(Agent, self).__init__()
        self.dagda_server_url = dagda_server_url
        self.analyzer = Analyzer(dagda_server_url=dagda_server_url)

    def run_static_analysis(self, image_name=None, container_id=None):
        evaluated_docker_image = self.analyzer.evaluate_image(image_name=image_name, container_id=container_id)
        print(evaluated_docker_image)
