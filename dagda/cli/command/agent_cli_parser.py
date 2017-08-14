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

import argparse
import sys
from log.dagda_logger import DagdaLogger


class AgentCLIParser:

    # -- Public methods

    # AgentDockerCLIParser Constructor
    def __init__(self):
        super(AgentCLIParser, self).__init__()
        self.parser = DagdaAgentParser(prog='dagda.py agent', usage=agent_parser_text)
        self.parser.add_argument('dagda_server', metavar='DAGDA_SERVER', type=str)
        self.parser.add_argument('-i', '--docker_image', type=str)
        self.parser.add_argument('-c', '--container_id', type=str)
        self.args, self.unknown = self.parser.parse_known_args(sys.argv[2:])
        # Verify command line arguments
        status = self.verify_args(self.args)
        if status != 0:
            exit(status)

    # -- Getters

    # Gets docker image name
    def get_docker_image_name(self):
        return self.args.docker_image

    # Gets docker container id
    def get_container_id(self):
        return self.args.container_id

    # Gets Dagda server endpoint
    def get_dagda_server(self):
        return self.args.dagda_server

    # -- Static methods

    # Verify command line arguments
    @staticmethod
    def verify_args(args):
        if not args.dagda_server:
            DagdaLogger.get_logger().error('Wrong Dagda server endpoint.')
            return 1
        else:
            splitted_info = args.dagda_server.split(':')
            if len(splitted_info) != 2:
                DagdaLogger.get_logger().error('Wrong Dagda server endpoint.')
                return 1
            try:
                port = int(splitted_info[1])
                if port not in range(1, 65536):
                    DagdaLogger.get_logger().error('Wrong Dagda server endpoint.')
                    return 1
            except ValueError:
                DagdaLogger.get_logger().error('Wrong Dagda server endpoint.')
                return 1

        if not args.container_id and not args.docker_image:
            DagdaLogger.get_logger().error('Missing arguments.')
            return 2
        elif args.container_id and args.docker_image:
            DagdaLogger.get_logger().error('Arguments --docker_image/--container_id: Both arguments '
                                           'can not be together.')
            return 3
        # Else
        return 0


# Custom parser

class DagdaAgentParser(argparse.ArgumentParser):

    # Overrides the error method
    def error(self, message):
        self.print_usage()
        exit(2)

    # Overrides the format help method
    def format_help(self):
        return agent_parser_text


# Custom text

agent_parser_text = '''usage: dagda.py agent [-h] DAGDA_HOST:DAGDA_PORT [-i DOCKER_IMAGE]
                  [-c CONTAINER_ID]

Your remote agent for analyzing docker images/containers.

Positional Arguments:
  DAGDA_HOST:DAGDA_PORT 
                        hostname and port where the Dagda server is listening. Only
                        "<DAGDA_HOST>:<DAGDA_PORT>" is accepted

Optional Arguments:
  -h, --help            show this help message and exit
  -i DOCKER_IMAGE, --docker_image DOCKER_IMAGE
                        the input docker image name
  -c CONTAINER_ID, --container_id CONTAINER_ID
                        the input docker container id
'''
