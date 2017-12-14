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
from dagda.api.service.vuln import get_vulns_by_product_and_version
from dagda.api.service.vuln import get_products_by_cve
from dagda.api.service.vuln import get_products_by_bid
from dagda.api.service.vuln import get_products_by_exploit_id
from dagda.api.service.vuln import get_products_by_rhsa
from dagda.api.service.vuln import get_products_by_rhba
from dagda.api.service.vuln import init_or_update_db
from dagda.api.service.vuln import get_init_or_update_db_status


# -- Test suite

class VulnApiTestCase(unittest.TestCase):

    # -- Mock internal classes

    class MockMongoDriverEmptyLists():
        def get_vulnerabilities(self, product, version):
            return []

        def get_products_by_cve(self, cve_id):
            return []

        def get_products_by_bid(self, bid_id):
            return []

        def get_products_by_exploit_db_id(self, exploit_id):
            return []

        def get_products_by_rhba(self, rhba_id):
            return []

        def get_products_by_rhsa(self, rhsa_id):
            return []

        def get_init_db_process_status(self):
            return {'timestamp': None}

    class MockMongoDriverWithContent():
        def get_vulnerabilities(self, product, version):
            return ['CVE-2002-2002']

        def get_products_by_cve(self, cve_id):
            return [{'product':'product_name', 'version': '1.0.0'}]

        def get_products_by_bid(self, bid_id):
            return [{'product':'product_name', 'version': '1.0.0'}]

        def get_products_by_exploit_db_id(self, exploit_id):
            return [{'product':'product_name', 'version': '1.0.0'}]

        def get_products_by_rhba(self, rhba_id):
            return [{'product':'product_name', 'version': '1.0.0'}]

        def get_products_by_rhsa(self, rhsa_id):
            return [{'product':'product_name', 'version': '1.0.0'}]

        def get_init_db_process_status(self):
            return {'timestamp': 123456789}

    class MockDagdaEdn():
        def put(self, msg):
            return

    # -- Tests

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmptyLists())
    def test_get_vulns_by_product_and_version_404(self, m):
        response, code = get_vulns_by_product_and_version('product')
        self.assertEqual(code, 404)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmptyLists())
    def test_get_products_by_cve_400(self, m):
        response, code = get_products_by_cve('product')
        self.assertEqual(code, 400)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmptyLists())
    def test_get_products_by_rhba_400(self, m):
        response, code = get_products_by_rhba('product')
        self.assertEqual(code, 400)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmptyLists())
    def test_get_products_by_rhsa_400(self, m):
        response, code = get_products_by_rhsa('product')
        self.assertEqual(code, 400)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmptyLists())
    def test_get_products_by_cve_404(self, m):
        response, code = get_products_by_cve('CVE-2002-2002')
        self.assertEqual(code, 404)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmptyLists())
    def test_get_products_by_bid_404(self, m):
        response, code = get_products_by_bid(1)
        self.assertEqual(code, 404)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmptyLists())
    def test_get_products_by_exploit_id_404(self, m):
        response, code = get_products_by_exploit_id(1)
        self.assertEqual(code, 404)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmptyLists())
    def test_get_products_by_rhba_404(self, m):
        response, code = get_products_by_rhba('RHBA-2012:2002')
        self.assertEqual(code, 404)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmptyLists())
    def test_get_products_by_rhsa_404(self, m):
        response, code = get_products_by_rhsa('RHSA-2012:2002')
        self.assertEqual(code, 404)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverWithContent())
    def test_get_vulns_by_product_and_version_200(self, m):
        response = get_vulns_by_product_and_version('product')
        self.assertEqual(response, '["CVE-2002-2002"]')

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverWithContent())
    def test_get_products_by_cve_200(self, m):
        response = get_products_by_cve('CVE-2002-2002')
        self.assertEqual(response, '[{"product": "product_name", "version": "1.0.0"}]')

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverWithContent())
    def test_get_products_by_bid_200(self, m):
        response = get_products_by_bid(1)
        self.assertEqual(response, '[{"product": "product_name", "version": "1.0.0"}]')

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverWithContent())
    def test_get_products_by_exploit_id_200(self, m):
        response = get_products_by_exploit_id(1)
        self.assertEqual(response, '[{"product": "product_name", "version": "1.0.0"}]')

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverWithContent())
    def test_get_products_by_rhba_200(self, m):
        response = get_products_by_rhba('RHBA-2012:2002')
        self.assertEqual(response, '[{"product": "product_name", "version": "1.0.0"}]')

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverWithContent())
    def test_get_products_by_rhsa_200(self, m):
        response = get_products_by_rhsa('RHSA-2012:2002')
        self.assertEqual(response, '[{"product": "product_name", "version": "1.0.0"}]')

    @patch('api.internal.internal_server.InternalServer.get_dagda_edn', return_value=MockDagdaEdn())
    def test_init_or_update_db_202(self, m):
        response, code = init_or_update_db()
        self.assertEqual(code, 202)

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverEmptyLists())
    def test_get_init_or_update_db_status_empty_timestamp(self, m):
        response = get_init_or_update_db_status()
        self.assertEqual(response, '{"timestamp": "-"}')

    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverWithContent())
    def test_get_init_or_update_db_status_with_timestamp(self, m):
        response = get_init_or_update_db_status()
        self.assertEqual(response, '{"timestamp": "1973-11-29 21:33:09"}')

if __name__ == '__main__':
    unittest.main()
