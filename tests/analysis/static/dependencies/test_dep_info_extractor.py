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
import json
import os
from dagda.analysis.static.dependencies.dep_info_extractor import get_filtered_dependencies_info
from dagda.analysis.static.dependencies.dep_info_extractor import read_4depcheck_output_file


# -- Test suite

class DepInfoExtractorTestSuite(unittest.TestCase):

    def test_raw_info_to_json_array(self):
        filtered_dep = get_filtered_dependencies_info(json.loads(mock_json_array), '/tmp/sdgas68kg')
        self.assertEqual(len(filtered_dep), 3)
        self.assertTrue('python#lxml#1.0.1#/tmp/lxml.1.0.1.py' in filtered_dep)
        self.assertTrue('java#cxf#2.6.0#/tmp/cxf.2.6.0.jar' in filtered_dep)
        self.assertTrue('java#navigator#4.08#/tmp/navigator.4.08.jar' in filtered_dep)

    def test_read_4depcheck_output_file_exception(self):
        msg = ''
        try:
            read_4depcheck_output_file('no_image_name')
        except Exception as ex:
            msg = ex.get_message()
        self.assertEqual(msg, '4depcheck output file [/tmp/4depcheck/no_image_name.json] not found.')

    def test_read_4depcheck_empty_output_file(self):
        # Prepare test
        try:
            os.makedirs('/tmp/4depcheck')
            created = True
        except OSError:
            created = False
        with open('/tmp/4depcheck/empty_output_file.json', 'w') as f:
            None
        # Run
        raw_info = read_4depcheck_output_file('empty_output_file')
        # Clean up
        os.remove('/tmp/4depcheck/empty_output_file.json')
        if created:
            os.removedirs('/tmp/4depcheck')
        # Check
        self.assertEqual(raw_info, '')


# -- Mock Constants

mock_json_array = '[{"cve_type": "python", "cve_product": "lxml", "cve_product_version": "1.0.1", "cve_product_file_path": "/tmp/lxml.1.0.1.py"}, {"cve_type": "java", "cve_product": "cxf", "cve_product_version": "2.6.0", "cve_product_file_path": "/tmp/cxf.2.6.0.jar"}, {"cve_type": "java", "cve_product": "navigator", "cve_product_version": "4.08", "cve_product_file_path": "/tmp/navigator.4.08.jar"}]'


if __name__ == '__main__':
    unittest.main()
