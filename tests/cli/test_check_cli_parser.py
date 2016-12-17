import unittest
import sys
from dagda.cli.check_cli_parser import CheckCLIParser


# -- Test suite

class CheckDockerImageCLIParserTestSuite(unittest.TestCase):

    def test_empty_args(self):
        empty_args = generate_args(None, None)
        status = CheckCLIParser.verify_args("dagda.py check", empty_args)
        self.assertEqual(status, 1)

    def test_both_arguments(self):
        args = generate_args('jboss/wildfly', '43a6ca974743')
        status = CheckCLIParser.verify_args("dagda.py check", args)
        self.assertEqual(status, 2)

    def test_ok_only_image_name(self):
        args = generate_args('jboss/wildfly', None)
        status = CheckCLIParser.verify_args("dagda.py check", args)
        self.assertEqual(status, 0)

    def test_ok_only_container_id(self):
        args = generate_args(None, '43a6ca974743')
        status = CheckCLIParser.verify_args("dagda.py check", args)
        self.assertEqual(status, 0)

    def test_check_full_happy_path(self):
        sys.argv = ['dagda.py', 'check', '-i', 'jboss/wildfly']
        parsed_args = CheckCLIParser()
        self.assertEqual(parsed_args.get_docker_image_name(), 'jboss/wildfly')


# -- Util methods

def generate_args(docker_image, container_id):
    return AttrDict([('container_id', container_id), ('docker_image', docker_image)])


# -- Util classes

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


if __name__ == '__main__':
    unittest.main()
