import unittest
import sys

from cli.command.monitor_cli_parser import MonitorCLIParser


class MonitorCLIParserTestCase(unittest.TestCase):

    def test_empty_args(self):
        empty_args = generate_args('69dbf26ab368', False, False)
        status = MonitorCLIParser.verify_args("dagda.py monitor", empty_args)
        self.assertEqual(status, 1)

    def test_all_args(self):
        empty_args = generate_args('69dbf26ab368', True, True)
        status = MonitorCLIParser.verify_args("dagda.py monitor", empty_args)
        self.assertEqual(status, 2)

    def test_check_full_happy_path(self):
        sys.argv = ['dagda.py', 'monitor', '69dbf26ab368', '--start']
        parsed_args = MonitorCLIParser()
        self.assertEqual(parsed_args.get_container_id(), '69dbf26ab368')


# -- Util methods

def generate_args(container_id, start, stop):
    return AttrDict([('container_id', container_id), ('start', start), ('stop', stop)])


# -- Util classes

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


if __name__ == '__main__':
    unittest.main()
