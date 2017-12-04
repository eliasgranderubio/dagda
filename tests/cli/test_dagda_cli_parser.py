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

from cli.dagda_cli_parser import DagdaCLIParser
from cli.dagda_cli_parser import DagdaGlobalParser
from cli.dagda_cli_parser import dagda_global_parser_text


# -- Test suite

class DagdaCLIParserTestSuite(unittest.TestCase):

    def test_dagda_check_full_happy_path(self):
        sys.argv = ['dagda.py', 'check', '-i', 'jboss/wildfly']
        parsed_args = DagdaCLIParser()
        self.assertEqual(parsed_args.get_command(), 'check')
        self.assertEqual(parsed_args.get_extra_args().get_docker_image_name(), 'jboss/wildfly')
        self.assertEqual(parsed_args.get_extra_args().get_container_id(), None)

    def test_dagda_history_full_happy_path(self):
        sys.argv = ['dagda.py', 'history', 'jboss/wildfly']
        parsed_args = DagdaCLIParser()
        self.assertEqual(parsed_args.get_command(), 'history')
        self.assertEqual(parsed_args.get_extra_args().get_docker_image_name(), 'jboss/wildfly')
        self.assertEqual(parsed_args.get_extra_args().get_report_id(), None)

    def test_dagda_monitor_full_happy_path(self):
        sys.argv = ['dagda.py', 'monitor', '69dbf26ab368', '--start']
        parsed_args = DagdaCLIParser()
        self.assertEqual(parsed_args.get_command(), 'monitor')
        self.assertEqual(parsed_args.get_extra_args().get_container_id(), '69dbf26ab368')
        self.assertTrue(parsed_args.get_extra_args().is_start())
        self.assertFalse(parsed_args.get_extra_args().is_stop())

    def test_dagda_vuln_full_happy_path(self):
        sys.argv = ['dagda.py', 'vuln', '--product', 'openldap', '--product_version', '2.2.20']
        parsed_args = DagdaCLIParser()
        self.assertEqual(parsed_args.get_command(), 'vuln')
        self.assertEqual(parsed_args.get_extra_args().get_product(), 'openldap')
        self.assertEqual(parsed_args.get_extra_args().get_product_version(), '2.2.20')
        self.assertFalse(parsed_args.get_extra_args().is_initialization_required())
        self.assertFalse(parsed_args.get_extra_args().is_init_status_requested())

    def test_dagda_start_full_happy_path(self):
        sys.argv = ['dagda.py', 'start', '--server_host', 'localhost', '--server_port', '5555']
        parsed_args = DagdaCLIParser()
        self.assertEqual(parsed_args.get_command(), 'start')
        self.assertEqual(parsed_args.get_extra_args().get_server_host(), 'localhost')
        self.assertEqual(parsed_args.get_extra_args().get_server_port(), 5555)
        self.assertEqual(parsed_args.get_extra_args().get_mongodb_host(), None)
        self.assertEqual(parsed_args.get_extra_args().get_mongodb_port(), None)

    def test_dagda_agent_full_happy_path(self):
        sys.argv = ['dagda.py', 'agent', 'localhost:5000', '-i', 'alpine']
        parsed_args = DagdaCLIParser()
        self.assertEqual(parsed_args.get_command(), 'agent')
        self.assertEqual(parsed_args.get_extra_args().get_dagda_server(), 'localhost:5000')
        self.assertEqual(parsed_args.get_extra_args().get_docker_image_name(), 'alpine')
        self.assertEqual(parsed_args.get_extra_args().get_container_id(), None)

    def test_dagda_docker_happy_path(self):
        sys.argv = ['dagda.py', 'docker', 'images', ]
        parsed_args = DagdaCLIParser()
        self.assertEqual(parsed_args.get_command(), 'docker')
        self.assertEqual(parsed_args.get_extra_args().get_command(), 'images')

    def test_check_exit_2(self):
        sys.argv = ['dagda.py', 'fake']
        with self.assertRaises(SystemExit) as cm:
            DagdaCLIParser()
        self.assertEqual(cm.exception.code, 2)

    def test_DagdaGlobalParser_exit_2(self):
        with self.assertRaises(SystemExit) as cm:
            DagdaGlobalParser().error("fail")
        self.assertEqual(cm.exception.code, 2)

    def test_DagdaGlobalParser_format_help(self):
        self.assertEqual(DagdaGlobalParser().format_help(), dagda_global_parser_text)
