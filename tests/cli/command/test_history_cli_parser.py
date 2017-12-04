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

import sys
import unittest

from cli.command.history_cli_parser import HistoryCLIParser
from cli.command.history_cli_parser import DagdaHistoryParser
from cli.command.history_cli_parser import history_parser_text


# -- Test suite

class DockerHistoryCLIParserTestCase(unittest.TestCase):

    def test_check_full_happy_path_1(self):
        sys.argv = ['dagda.py', 'history', 'jboss/wildfly']
        parsed_args = HistoryCLIParser()
        self.assertEqual(parsed_args.get_docker_image_name(), 'jboss/wildfly')
        self.assertEqual(parsed_args.get_fp(), None)
        self.assertEqual(parsed_args.get_is_fp(), None)

    def test_check_full_happy_path_2(self):
        sys.argv = ['dagda.py', 'history', 'jboss/wildfly', '--fp', 'openldap:2.2.20']
        parsed_args = HistoryCLIParser()
        self.assertEqual(parsed_args.get_docker_image_name(), 'jboss/wildfly')
        self.assertEqual(parsed_args.get_fp()[0], 'openldap')
        self.assertEqual(parsed_args.get_fp()[1], '2.2.20')
        self.assertEqual(parsed_args.get_is_fp(), None)

    def test_check_full_happy_path_3(self):
        sys.argv = ['dagda.py', 'history', 'jboss/wildfly', '--fp', 'mongodb']
        parsed_args = HistoryCLIParser()
        self.assertEqual(parsed_args.get_docker_image_name(), 'jboss/wildfly')
        self.assertEqual(parsed_args.get_fp()[0], 'mongodb')
        self.assertEqual(parsed_args.get_fp()[1], None)
        self.assertEqual(parsed_args.get_is_fp(), None)

    def test_both_arguments(self):
        empty_args = generate_args(None, '43a6ca974743', 'openldap:2.2.20', None)
        status = HistoryCLIParser.verify_args(empty_args)
        self.assertEqual(status, 1)

    def test_missing_image_name(self):
        args = generate_args(None, None, 'openldap:2.2.20', None)
        status = HistoryCLIParser.verify_args(args)
        self.assertEqual(status, 2)

    def test_both_arguments_with_is_fp(self):
        empty_args = generate_args(None, '43a6ca974743', None, 'openldap:2.2.20')
        status = HistoryCLIParser.verify_args(empty_args)
        self.assertEqual(status, 3)

    def test_missing_image_name_with_is_fp(self):
        args = generate_args(None, None, None, 'openldap:2.2.20')
        status = HistoryCLIParser.verify_args(args)
        self.assertEqual(status, 4)

    def test_ok_only_image_name(self):
        args = generate_args('jboss/wildfly', None, None, None)
        status = HistoryCLIParser.verify_args(args)
        self.assertEqual(status, 0)

    def test_none_fp(self):
        self.assertIsNone(HistoryCLIParser()._parse_product_and_version(None))

    def test_is_fp(self):
        sys.argv = ['dagda.py', 'history', 'jboss/wildfly', '--is_fp', 'openldap:2.2.20']
        args = HistoryCLIParser()
        self.assertEqual(args.get_is_fp(), ('openldap', '2.2.20'))

    def test_check_exit_1(self):
        sys.argv = ['dagda.py', 'history', '--id', '43a6ca974743', '--fp', 'openldap:2.2.20']
        with self.assertRaises(SystemExit) as cm:
            HistoryCLIParser()
        self.assertEqual(cm.exception.code, 1)

    def test_DagdaHistoryParser_exit_2(self):
        with self.assertRaises(SystemExit) as cm:
            DagdaHistoryParser().error("fail")
        self.assertEqual(cm.exception.code, 2)

    def test_DagdaHistoryParser_format_help(self):
        self.assertEqual(DagdaHistoryParser().format_help(), history_parser_text)


# -- Util methods

def generate_args(docker_image_name, id, fp, is_fp):
    return AttrDict([('docker_image_name', docker_image_name), ('id', id), ('fp', fp), ('is_fp', is_fp)])


# -- Util classes

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

if __name__ == '__main__':
    unittest.main()
