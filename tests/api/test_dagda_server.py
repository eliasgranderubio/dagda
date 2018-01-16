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
import requests
import time
import json
from unittest.mock import Mock
from api.dagda_server import DagdaServer


# -- Test suite

class DagdaServerTestCase(unittest.TestCase):

    def test_error_messages(self):
        ds = DagdaServerWithoutSysdigFalcoMonitor('127.0.0.1', 55555)
        bad_rs, bad_code = ds.bad_request()
        not_found_rs, not_found_code = ds.not_found()
        internal_rs, internal_code = ds.internal_server_error()
        self.assertEqual(bad_code, 400)
        self.assertEqual(not_found_code, 404)
        self.assertEqual(internal_code, 500)
        self.assertEqual(json.loads(bad_rs)['msg'], 'Bad Request')
        self.assertEqual(json.loads(not_found_rs)['msg'], 'Not Found')
        self.assertEqual(json.loads(internal_rs)['msg'], 'Internal Server Error')


# -- Mock classes

class DagdaServerWithoutSysdigFalcoMonitor(DagdaServer):
    def __init__(self, dagda_server_host='127.0.0.1', dagda_server_port=5000, mongodb_host='127.0.0.1',
                 mongodb_port=27017):
        super(DagdaServer, self).__init__()
        self.dagda_server_host = dagda_server_host
        self.dagda_server_port = dagda_server_port
        self.sysdig_falco_monitor = Mock()
        self.sysdig_falco_monitor.pre_check.return_value = 0
        self.sysdig_falco_monitor.run.return_value = 0


if __name__ == '__main__':
    unittest.main()
