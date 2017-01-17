import sys
import unittest

from cli.command.history_cli_parser import HistoryCLIParser


# -- Test suite

class DockerHistoryCLIParserTestCase(unittest.TestCase):

    def test_check_full_happy_path(self):
        sys.argv = ['dagda.py', 'history', 'jboss/wildfly']
        parsed_args = HistoryCLIParser()
        self.assertEqual(parsed_args.get_docker_image_name(), 'jboss/wildfly')


if __name__ == '__main__':
    unittest.main()
