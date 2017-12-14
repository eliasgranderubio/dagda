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
from cli.command.check_cli_parser import CheckCLIParser
from cli.command.docker_cli_parser import DockerCLIParser
from cli.command.history_cli_parser import HistoryCLIParser
from cli.command.vuln_cli_parser import VulnCLIParser
from cli.command.start_cli_parser import StartCLIParser
from cli.command.monitor_cli_parser import MonitorCLIParser
from cli.command.agent_cli_parser import AgentCLIParser


class DagdaCLIParser:

    # -- Public methods

    # DagdaCLIParser Constructor
    def __init__(self):
        super(DagdaCLIParser, self).__init__()
        self.parser = DagdaGlobalParser(prog='dagda.py', usage=dagda_global_parser_text, add_help=False)
        self.parser.add_argument('command', choices=['vuln', 'check', 'history', 'start', 'monitor', 'docker', 'agent'])
        self.parser.add_argument('-h', '--help', action=_HelpAction)
        self.parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.7.0')
        self.args, self.unknown = self.parser.parse_known_args()
        if self.get_command() == 'vuln':
            self.extra_args = VulnCLIParser()
        elif self.get_command() == 'check':
            self.extra_args = CheckCLIParser()
        elif self.get_command() == 'history':
            self.extra_args = HistoryCLIParser()
        elif self.get_command() == 'start':
            self.extra_args = StartCLIParser()
        elif self.get_command() == 'monitor':
            self.extra_args = MonitorCLIParser()
        elif self.get_command() == 'docker':
            self.extra_args = DockerCLIParser()
        elif self.get_command() == 'agent':
            self.extra_args = AgentCLIParser()

    # -- Getters

    # Gets command
    def get_command(self):
        return self.args.command

    # Gets extra args
    def get_extra_args(self):
        return self.extra_args


# Overrides Help Action class

class _HelpAction(argparse._HelpAction):

    def __call__(self, parser, namespace, values, option_string=None):
        if sys.argv[1] != 'vuln' and sys.argv[1] != 'check' and sys.argv[1] != 'history' and sys.argv[1] != 'start' \
                and sys.argv[1] != 'monitor' and sys.argv[1] != 'docker' and sys.argv[1] != 'agent':
            parser.print_help()
            parser.exit()


# Custom Parser

class DagdaGlobalParser(argparse.ArgumentParser):

    # Overrides the error method
    def error(self, message):
        self.print_usage()
        exit(2)

    # Overrides the format help method
    def format_help(self):
        return dagda_global_parser_text


# -- Custom message

dagda_global_parser_text = '''usage: dagda.py [--version] [--help] <command> [args]

Dagda Commands:
  agent                 run a remote agent for performing the analysis of known 
                        vulnerabilities, trojans, viruses, malware & other 
                        malicious threats in docker images/containers
  check                 perform the analysis of known vulnerabilities, trojans, 
                        viruses, malware & other malicious threats in docker 
                        images/containers
  docker                list all docker images/containers
  history               retrieve the analysis history for the docker images
  monitor               perform the monitoring of anomalous activities in
                        running docker containers
  start                 start the Dagda server
  vuln                  perform operations over your personal CVE, BID, RHBA, 
                        RHSA & ExploitDB database

Optional Arguments:
  -h, --help            show this help message and exit
  -v, --version         show the version message and exit
'''
