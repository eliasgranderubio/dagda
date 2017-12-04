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

import sys
import unittest

from cli.command.agent_cli_parser import AgentCLIParser
from cli.command.agent_cli_parser import agent_parser_text
from cli.command.agent_cli_parser import DagdaAgentParser


# -- Test suite

class AgentCLIParserTestSuite(unittest.TestCase):

    def test_empty_args(self):
        empty_args = generate_args(None, None, None)
        status = AgentCLIParser.verify_args(empty_args)
        self.assertEqual(status, 1)

    def test_wrong_dagda_server_1(self):
        wrong_args = generate_args('localhost:asdfg67', None, None)
        status = AgentCLIParser.verify_args(wrong_args)
        self.assertEqual(status, 1)

    def test_wrong_dagda_server_2(self):
        wrong_args = generate_args('localhost', None, None)
        status = AgentCLIParser.verify_args(wrong_args)
        self.assertEqual(status, 1)

    def test_wrong_dagda_server_3(self):
        wrong_args = generate_args('localhost:66666', None, None)
        status = AgentCLIParser.verify_args(wrong_args)
        self.assertEqual(status, 1)

    def test_empty_optional_args(self):
        wrong_args = generate_args('localhost:5000', None, None)
        status = AgentCLIParser.verify_args(wrong_args)
        self.assertEqual(status, 2)

    def test_both_arguments(self):
        args = generate_args('localhost:5000', 'jboss/wildfly', '43a6ca974743')
        status = AgentCLIParser.verify_args(args)
        self.assertEqual(status, 3)

    def test_ok_only_container_id(self):
        args = generate_args('localhost:5000', None, '43a6ca974743')
        status = AgentCLIParser.verify_args(args)
        self.assertEqual(status, 0)

    def test_check_full_happy_path(self):
        sys.argv = ['dagda.py', 'agent', 'localhost:5000', '-i', 'jboss/wildfly']
        parsed_args = AgentCLIParser()
        self.assertEqual(parsed_args.get_docker_image_name(), 'jboss/wildfly')

    def test_check_exit_2(self):
        sys.argv = ['dagda.py', 'agent']
        with self.assertRaises(SystemExit) as cm:
            AgentCLIParser()
        self.assertEqual(cm.exception.code, 2)

    def test_DagdaAgentParser_exit_2(self):
        with self.assertRaises(SystemExit) as cm:
            DagdaAgentParser().error("fail")
        self.assertEqual(cm.exception.code, 2)

    def test_DagdaAgentParser_format_help(self):
        self.assertEqual(DagdaAgentParser().format_help(), agent_parser_text)


# -- Util methods

def generate_args(dagda_server, docker_image, container_id):
    return AttrDict([('dagda_server', dagda_server), ('container_id', container_id),
                     ('docker_image', docker_image)])


# -- Util classes

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


if __name__ == '__main__':
    unittest.main()
