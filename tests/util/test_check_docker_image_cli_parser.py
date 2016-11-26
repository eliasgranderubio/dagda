import unittest
from dagda.util.check_docker_image_cli_parser import CheckDockerImageCLIParser


# -- Test suite

class CheckDockerImageCLIParserTestSuite(unittest.TestCase):

    def test_empty_args(self):
        empty_args = generate_args(None, None, False)
        status = CheckDockerImageCLIParser.verify_args("check_docker_image.py", empty_args)
        self.assertEqual(status, 1)

    def test_only_show_history(self):
        args = generate_args(None, None, True)
        status = CheckDockerImageCLIParser.verify_args("check_docker_image.py", args)
        self.assertEqual(status, 1)

    def test_bad_show_history(self):
        args = generate_args(None, '43a6ca974743', True)
        status = CheckDockerImageCLIParser.verify_args("check_docker_image.py", args)
        self.assertEqual(status, 2)

    def test_ok_show_history(self):
        args = generate_args('jboss/wildfly', None, True)
        status = CheckDockerImageCLIParser.verify_args("check_docker_image.py", args)
        self.assertEqual(status, 0)

    def test_ok_only_container_id(self):
        args = generate_args(None, '43a6ca974743', False)
        status = CheckDockerImageCLIParser.verify_args("check_docker_image.py", args)
        self.assertEqual(status, 0)


# -- Util methods

def generate_args(docker_image, container_id, show_history):
    return AttrDict([('container_id', container_id), ('docker_image', docker_image), ('show_history', show_history)])


# -- Util classes

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


if __name__ == '__main__':
    unittest.main()
