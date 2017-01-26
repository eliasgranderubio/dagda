import unittest
from cli.command.start_cli_parser import StartCLIParser


# -- Test suite

class StartCLIParserTestCase(unittest.TestCase):

    def test_ok_empty_args(self):
        args = generate_args(None, None, None, None, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 0)

    def test_ok_server_ports(self):
        args = generate_args(None, 5555, None, 27017, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 0)

    def test_fail_server_port(self):
        args = generate_args(None, 65536, None, None, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 1)

    def test_fail_mongodb_port(self):
        args = generate_args(None, None, None, 65536, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 2)

# -- Util methods

def generate_args(server_host, server_port, mongodb_host, mongodb_port, falco_rules_file):
    return AttrDict([('server_host', server_host), ('server_port', server_port), ('mongodb_host', mongodb_host),
                     ('mongodb_port', mongodb_port), ('falco_rules_file', falco_rules_file)])


# -- Util classes

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


if __name__ == '__main__':
    unittest.main()
