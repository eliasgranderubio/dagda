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
import os
import sys
import tempfile
import shutil
from cli.command.start_cli_parser import StartCLIParser


# -- Test suite

class StartCLIParserTestCase(unittest.TestCase):

    def test_ok_empty_args(self):
        args = generate_args(None, None, None, None, False, None, None, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 0)

    def test_ok_server_ports(self):
        args = generate_args(None, 5555, None, 27017, False, None, None, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 0)

    def test_fail_server_port(self):
        args = generate_args(None, 65536, None, None, False, None, None, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 1)

    def test_fail_mongodb_port(self):
        args = generate_args(None, None, None, 65536, False, None, None, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 2)

    def test_fail_only_mongodb_user(self):
        args = generate_args(None, None, None, None, False, 'admin', None, None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 3)

    def test_fail_only_mongodb_pass(self):
        args = generate_args(None, None, None, None, False, None, '1234', None)
        status = StartCLIParser.verify_args(args)
        self.assertEqual(status, 4)

    def test_fail_falco_rules(self):
        temporary_dir = tempfile.mkdtemp()
        filename = temporary_dir + '/fail_falco_rules'
        with open(filename, 'a+') as f:
            f.write('{}$##')
            f.flush()
        args = generate_args(None, None, None, None, False, None, None, open(filename, 'rb+'))
        status = StartCLIParser.verify_args(args)
        os.remove(filename)
        shutil.rmtree(temporary_dir)
        self.assertEqual(status, 5)

    def test_start_full_happy_path(self):
        sys.argv = ['dagda.py', 'start', '-s', '127.0.0.1', '-p', '5000', '-m', '127.0.0.1', '-mp', '27017']
        parsed_args = StartCLIParser()
        self.assertEqual(parsed_args.get_server_host(), '127.0.0.1')
        self.assertEqual(parsed_args.get_server_port(), 5000)
        self.assertEqual(parsed_args.get_mongodb_host(), '127.0.0.1')
        self.assertEqual(parsed_args.get_mongodb_port(), 27017)
        self.assertFalse(parsed_args.is_mongodb_ssl_enabled())
        self.assertIsNone(parsed_args.get_mongodb_user())
        self.assertIsNone(parsed_args.get_mongodb_pass())
        self.assertIsNone(parsed_args.get_falco_rules_filename())


# -- Util methods

def generate_args(server_host, server_port, mongodb_host, mongodb_port, mongodb_ssl, mongodb_user, mongodb_pass,
                  falco_rules_file):
    return AttrDict([('server_host', server_host), ('server_port', server_port), ('mongodb_host', mongodb_host),
                     ('mongodb_port', mongodb_port), ('mongodb_ssl', mongodb_ssl), ('mongodb_user', mongodb_user),
                     ('mongodb_pass', mongodb_pass), ('falco_rules_file', falco_rules_file)])


# -- Util classes

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


if __name__ == '__main__':
    unittest.main()
