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

from cli.command.check_cli_parser import CheckCLIParser


# -- Test suite

class CheckDockerImageCLIParserTestSuite(unittest.TestCase):

    def test_empty_args(self):
        empty_args = generate_args(None, None)
        status = CheckCLIParser.verify_args(empty_args)
        self.assertEqual(status, 1)

    def test_both_arguments(self):
        args = generate_args('jboss/wildfly', '43a6ca974743')
        status = CheckCLIParser.verify_args(args)
        self.assertEqual(status, 2)

    def test_ok_only_image_name(self):
        args = generate_args('jboss/wildfly', None)
        status = CheckCLIParser.verify_args(args)
        self.assertEqual(status, 0)

    def test_ok_only_container_id(self):
        args = generate_args(None, '43a6ca974743')
        status = CheckCLIParser.verify_args(args)
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
