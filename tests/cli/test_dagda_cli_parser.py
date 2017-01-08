import sys
import unittest

from cli.dagda_cli_parser import DagdaCLIParser


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
