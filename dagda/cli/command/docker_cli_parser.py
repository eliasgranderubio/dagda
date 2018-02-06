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


class DockerCLIParser:

    # -- Public methods

    # DockerCLIParser Constructor
    def __init__(self):
        super(DockerCLIParser, self).__init__()
        self.parser = DagdaDockerParser(prog='dagda.py docker', usage=docker_parser_text)
        self.parser.add_argument('command', choices=['containers', 'images', 'events'])
        self.parser.add_argument('--event_action', type=str)
        self.parser.add_argument('--event_from', type=str)
        self.parser.add_argument('--event_type', type=str)
        self.args, self.unknown = self.parser.parse_known_args(sys.argv[2:])
        # Verify command line arguments
        status = self.verify_args(self.args, sys.argv)
        if status != 0:
            exit(status)

    # -- Getters

    # Gets command
    def get_command(self):
        return self.args.command

    # Gets event action
    def get_event_action(self):
        return self.args.event_action

    # Gets event from
    def get_event_from(self):
        return self.args.event_from

    # Gets event type
    def get_event_type(self):
        return self.args.event_type

    # -- Static methods

    # Verify command line arguments
    @staticmethod
    def verify_args(args, sys_argv):
        if sys_argv[2] not in ['containers', 'images', 'events']:
            DagdaLogger.get_logger().error('Missing arguments.')
            return 1
        elif (args.command == 'containers' or args.command == 'images') and \
           (args.event_action or args.event_from or args.event_type):
            DagdaLogger.get_logger().error('Command <' + args.command + '>: this command must be alone.')
            return 2
        # Else
        return 0


# Custom parser

class DagdaDockerParser(argparse.ArgumentParser):

    # Overrides the error method
    def error(self, message):
        self.print_usage()
        exit(2)

    # Overrides the format help method
    def format_help(self):
        return docker_parser_text


# Custom text

docker_parser_text = '''usage: dagda.py docker [-h] <command> [--event_action ACTION] 
                  [--event_from FROM] [--event_type TYPE] 

Your personal docker API.

Dagda Commands:
  containers            list all running docker containers
  events                list all docker daemon events
  images                list all docker images

Optional Arguments:
  -h, --help            show this help message and exit
  
  --event_from FROM     Filter for docker daemon events
  --event_type TYPE     Filter for docker daemon events
  --event_action ACTION 
                        Filter for docker daemon events
'''