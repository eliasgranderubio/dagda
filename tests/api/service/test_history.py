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
from unittest.mock import patch
import json

from dagda.api.service.history import get_history
from dagda.api.service.history import set_product_vulnerability_as_false_positive
from dagda.api.service.history import is_product_vulnerability_a_false_positive


# -- Test suite

class HistoryApiTestCase(unittest.TestCase):

    # -- Mock internal classes

    class MockMongoDriver():

        def get_docker_image_all_history(self):
            return [{}]

        def update_product_vulnerability_as_fp(self, image_name, product, version=None):
            return True

        def is_fp(self, image_name, product, version=None):
            return True

    class MockMongoDriverEmpty():

        def get_docker_image_all_history(self):
            return []

        def update_product_vulnerability_as_fp(self, image_name, product, version=None):
            return False

        def is_fp(self, image_name, product, version=None):
            return False

    # -- Tests

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmpty())
    def test_get_history_404(self, m1):
        response, code = get_history()
        self.assertEqual(code, 404)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriver())
    def test_get_history_200(self, m1):
        response = get_history()
        self.assertEqual(response, json.dumps([{}]))

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmpty())
    def test_set_product_vulnerability_as_false_positive_404(self, m1):
        response, code = set_product_vulnerability_as_false_positive('fake_image_name', 'product_name')
        self.assertEqual(code, 404)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriver())
    def test_set_product_vulnerability_as_false_positive_204(self, m1):
        response, code = set_product_vulnerability_as_false_positive('fake_image_name', 'product_name')
        self.assertEqual(code, 204)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmpty())
    def test_is_product_vulnerability_a_false_positive_404(self, m1):
        response, code = is_product_vulnerability_a_false_positive('fake_image_name', 'product_name')
        self.assertEqual(code, 404)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriver())
    def test_is_product_vulnerability_a_false_positive_204(self, m1):
        response, code = is_product_vulnerability_a_false_positive('fake_image_name', 'product_name')
        self.assertEqual(code, 204)
