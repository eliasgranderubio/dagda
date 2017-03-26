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

import multiprocessing
from driver.mongodb_driver import MongoDbDriver
from driver.docker_driver import DockerDriver


# Internal Dagda server class

class InternalServer:

    # -- Global attributes

    _dagda_edn = multiprocessing.Queue()
    _mongodb_driver = MongoDbDriver()
    _docker_driver = DockerDriver()

    # -- Static methods

    # Gets Dagda EDN
    @staticmethod
    def get_dagda_edn():
        return InternalServer._dagda_edn

    # Gets MongoDB Driver
    @staticmethod
    def get_mongodb_driver():
        return InternalServer._mongodb_driver

    # Sets MongoDB Driver
    @staticmethod
    def set_mongodb_driver(mongodb_host, mongodb_port, mongodb_ssl, mongodb_user, mongodb_pass):
        if not mongodb_host:
            mongodb_host = '127.0.0.1'
        if not mongodb_port:
            mongodb_port = 27017
        if not mongodb_ssl:
            mongodb_ssl = False
        if not mongodb_user:
            mongodb_user = None
        if not mongodb_pass:
            mongodb_pass = None
        InternalServer._mongodb_driver = MongoDbDriver(mongodb_host, mongodb_port, mongodb_ssl,
                                                       mongodb_user, mongodb_pass)

    # Gets Docker Driver
    @staticmethod
    def get_docker_driver():
        return InternalServer._docker_driver

    # Is runtime analysis enabled
    @staticmethod
    def is_runtime_analysis_enabled():
        return len(InternalServer._docker_driver.get_docker_container_ids_by_image_name('sysdig/falco')) > 0

