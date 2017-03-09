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

import unittest
import sys

from cli.command.monitor_cli_parser import MonitorCLIParser


class MonitorCLIParserTestCase(unittest.TestCase):

    def test_empty_args(self):
        empty_args = generate_args('69dbf26ab368', False, False)
        status = MonitorCLIParser.verify_args(empty_args)
        self.assertEqual(status, 1)

    def test_all_args(self):
        empty_args = generate_args('69dbf26ab368', True, True)
        status = MonitorCLIParser.verify_args(empty_args)
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
