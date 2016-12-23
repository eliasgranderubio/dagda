import sys
import unittest

from cli.command.history_cli_parser import HistoryCLIParser


# -- Test suite

class DockerHistoryCLIParserTestCase(unittest.TestCase):

    def test_empty_args(self):
        empty_args = generate_args(None)
        status = HistoryCLIParser.verify_args("dagda.py history", empty_args)
        self.assertEqual(status, 1)

    def test_ok_args(self):
        empty_args = generate_args('jboss/wildfly')
        status = HistoryCLIParser.verify_args("dagda.py history", empty_args)
        self.assertEqual(status, 0)

    def test_check_full_happy_path(self):
        sys.argv = ['dagda.py', 'history', 'jboss/wildfly']
        parsed_args = HistoryCLIParser()
        self.assertEqual(parsed_args.get_docker_image_name(), 'jboss/wildfly')


# -- Util methods

def generate_args(docker_image_name):
    return AttrDict([('docker_image_name', docker_image_name)])


# -- Util classes

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


if __name__ == '__main__':
    unittest.main()
