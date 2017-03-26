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
from cli.command.start_cli_parser import StartCLIParser


# -- Test suite

class StartCLIParserTestCase(unittest.TestCase):

    def test_ok_empty_args(self):
        args = generate_args(None, None, None, None, False, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 0)

    def test_ok_server_ports(self):
        args = generate_args(None, 5555, None, 27017, False, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 0)

    def test_fail_server_port(self):
        args = generate_args(None, 65536, None, None, False, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 1)

    def test_fail_mongodb_port(self):
        args = generate_args(None, None, None, 65536, False, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 2)


# -- Util methods

def generate_args(server_host, server_port, mongodb_host, mongodb_port, mongodb_ssl, falco_rules_file):
    return AttrDict([('server_host', server_host), ('server_port', server_port), ('mongodb_host', mongodb_host),
                     ('mongodb_port', mongodb_port), ('mongodb_ssl', mongodb_ssl),
                     ('falco_rules_file', falco_rules_file)])


# -- Util classes

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


if __name__ == '__main__':
    unittest.main()
