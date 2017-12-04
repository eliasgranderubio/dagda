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

from cli.command.docker_cli_parser import docker_parser_text
from cli.command.docker_cli_parser import DagdaDockerParser


# -- Test suite

class DockerCLIParserTestSuite(unittest.TestCase):

    def test_DagdaDockerParser_exit_2(self):
        with self.assertRaises(SystemExit) as cm:
            DagdaDockerParser().error("fail")
        self.assertEqual(cm.exception.code, 2)

    def test_DagdaDockerParser_format_help(self):
        self.assertEqual(DagdaDockerParser().format_help(), docker_parser_text)
