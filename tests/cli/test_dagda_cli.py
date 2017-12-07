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

import os
import sys
import requests
import unittest
from cli.dagda_cli_parser import DagdaCLIParser
from cli.dagda_cli import execute_dagda_cmd
from cli.dagda_cli import _get_dagda_base_url


# -- Test suite

class DagdaCLITestSuite(unittest.TestCase):

    def test_dagda_check_image_full_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'check', '-i', 'jboss/wildfly']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/check/images/jboss/wildfly')

    def test_dagda_check_container_full_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'check', '-c', '697f6f235558']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/check/containers/697f6f235558')

    def test_dagda_docker_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'docker', 'images']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/docker/images')

    def test_dagda_monitor_start_full_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'monitor', '69dbf26ab368', '--start']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/monitor/containers/69dbf26ab368/start')

    def test_dagda_monitor_stop_full_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'monitor', '69dbf26ab368', '--stop']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/monitor/containers/69dbf26ab368/stop')

    def test_dagda_history_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'history']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/history')

    def test_dagda_history_full_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'history', 'jboss/wildfly']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/history/jboss/wildfly')

    def test_dagda_history_id_full_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'history', 'jboss/wildfly', '--id', '69dbf26ab368']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/history/jboss/wildfly?id=69dbf26ab368')

    def test_dagda_history_fp_full_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'history', 'jboss/wildfly', '--fp', 'openldap:2.2.20']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/history/jboss/wildfly/fp/openldap/2.2.20')

    def test_dagda_history_is_fp_full_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'history', 'jboss/wildfly', '--is_fp', 'openldap']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/history/jboss/wildfly/fp/openldap')

    def test_dagda_vuln_init_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'vuln', '--init']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/vuln/init')

    def test_dagda_vuln_init_status_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'vuln', '--init_status']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/vuln/init-status')

    def test_dagda_vuln_cve_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'vuln', '--cve', 'CVE-2002-2002']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/vuln/cve/CVE-2002-2002')

    def test_dagda_vuln_cve_info_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'vuln', '--cve_info', 'CVE-2002-2002']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/vuln/cve/CVE-2002-2002/details')

    def test_dagda_vuln_bid_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'vuln', '--bid', '2002']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/vuln/bid/2002')

    def test_dagda_vuln_bid_info_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'vuln', '--bid_info', '2002']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/vuln/bid/2002/details')

    def test_dagda_vuln_exploit_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'vuln', '--exploit_db', '2002']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/vuln/exploit/2002')

    def test_dagda_vuln_exploit_info_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'vuln', '--exploit_db_info', '2002']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/vuln/exploit/2002/details')

    def test_dagda_vuln_product_version_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'vuln', '--product', 'openldap', '--product_version', '2.2.20']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/vuln/products/openldap/2.2.20')

    def test_dagda_vuln_product_happy_path(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        sys.argv = ['dagda.py', 'vuln', '--product', 'openldap']
        parsed_args = DagdaCLIParser()
        try:
            execute_dagda_cmd(parsed_args.get_command(), parsed_args.get_extra_args())
            self.fail()
        except requests.exceptions.ConnectionError as err:
            err = DagdaCLITestSuite._get_path(err)
            self.assertEqual(err, '/v1/vuln/products/openldap')








    def test_empty_dagda_host_and_port_exit_1(self):
        try:
            del os.environ['DAGDA_HOST']
        except KeyError:
            pass
        try:
            del os.environ['DAGDA_PORT']
        except KeyError:
            pass
        with self.assertRaises(SystemExit) as cm:
            _get_dagda_base_url()
        self.assertEqual(cm.exception.code, 1)

    def test_empty_dagda_port_exit_1(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        try:
            del os.environ['DAGDA_PORT']
        except KeyError:
            pass
        with self.assertRaises(SystemExit) as cm:
            _get_dagda_base_url()
        self.assertEqual(cm.exception.code, 1)

    def test_with_dagda_host_and_port(self):
        os.environ['DAGDA_HOST'] = str('localhost')
        os.environ['DAGDA_PORT'] = str('50000')
        self.assertEqual(_get_dagda_base_url(), 'http://localhost:50000/v1')

    # -- Private methods

    # Gets path from python error
    @staticmethod
    def _get_path(err):
        err = str(err)[81:]
        return err[:err.index(' ')]








    #
    #

    #
    # def test_dagda_start_full_happy_path(self):
    #     sys.argv = ['dagda.py', 'start', '--server_host', 'localhost', '--server_port', '5555']
    #     parsed_args = DagdaCLIParser()
    #     self.assertEqual(parsed_args.get_command(), 'start')
    #     self.assertEqual(parsed_args.get_extra_args().get_server_host(), 'localhost')
    #     self.assertEqual(parsed_args.get_extra_args().get_server_port(), 5555)
    #     self.assertEqual(parsed_args.get_extra_args().get_mongodb_host(), None)
    #     self.assertEqual(parsed_args.get_extra_args().get_mongodb_port(), None)
    #
    # def test_dagda_agent_full_happy_path(self):
    #     sys.argv = ['dagda.py', 'agent', 'localhost:5000', '-i', 'alpine']
    #     parsed_args = DagdaCLIParser()
    #     self.assertEqual(parsed_args.get_command(), 'agent')
    #     self.assertEqual(parsed_args.get_extra_args().get_dagda_server(), 'localhost:5000')
    #     self.assertEqual(parsed_args.get_extra_args().get_docker_image_name(), 'alpine')
    #     self.assertEqual(parsed_args.get_extra_args().get_container_id(), None)
