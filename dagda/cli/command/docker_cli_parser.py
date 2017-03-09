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


class DockerCLIParser:

    # -- Public methods

    # DockerCLIParser Constructor
    def __init__(self):
        super(DockerCLIParser, self).__init__()
        self.parser = DagdaDockerParser(prog='dagda.py docker', usage=docker_parser_text)
        self.parser.add_argument('command', choices=['containers', 'images'])
        self.args, self.unknown = self.parser.parse_known_args(sys.argv[2:])

    # -- Getters

    # Gets command
    def get_command(self):
        return self.args.command


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

docker_parser_text = '''usage: dagda.py docker [-h] <command>

Your personal docker API.


Dagda Commands:
  containers            list all running docker containers
  images                list all docker images


Optional Arguments:
  -h, --help            show this help message and exit
'''