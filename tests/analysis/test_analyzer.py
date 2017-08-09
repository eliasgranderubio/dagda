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
from unittest.mock import Mock

import sys, os
sys.path.insert(1, str(os.path.dirname(os.path.abspath(__file__))) + '/../../dagda')
from analysis.analyzer import Analyzer


# -- Test suite

class AnalyzerTestCase(unittest.TestCase):

    def test_generate_os_report_with_empty_dep(self):
        analyzer = EmptyVulnArrayAnalyzer()
        report = analyzer.generate_os_report('test_image_name', [])
        self.assertEqual(report['total_os_packages'], 0)
        self.assertEqual(report['vuln_os_packages'], 0)
        self.assertEqual(report['ok_os_packages'], 0)
        self.assertEqual(len(report['os_packages_details']), 0)

    def test_generate_os_report_with_NOT_empty_dep(self):
        analyzer = NotEmptyVulnArrayAnalyzer()
        report = analyzer.generate_os_report('test_image_name', [{'product': 'java', 'version': '1.5'}])
        self.assertEqual(report['total_os_packages'], 1)
        self.assertEqual(report['vuln_os_packages'], 1)
        self.assertEqual(report['ok_os_packages'], 0)
        self.assertEqual(len(report['os_packages_details']), 1)
        self.assertEqual(report['os_packages_details'][0]['product'], 'java')
        self.assertEqual(report['os_packages_details'][0]['version'], '1.5')
        self.assertEqual(len(report['os_packages_details'][0]['vulnerabilities']), 6)

    def test_generate_os_report_with_NOT_empty_dep_with_fp(self):
        analyzer = NotEmptyVulnArrayWithFalsePositivesAnalyzer()
        report = analyzer.generate_os_report('test_image_name', [{'product': 'java', 'version': '1.5'}])
        self.assertEqual(report['total_os_packages'], 1)
        self.assertEqual(report['vuln_os_packages'], 0)
        self.assertEqual(report['ok_os_packages'], 1)
        self.assertEqual(len(report['os_packages_details']), 1)
        self.assertEqual(report['os_packages_details'][0]['product'], 'java')
        self.assertEqual(report['os_packages_details'][0]['version'], '1.5')
        self.assertEqual(len(report['os_packages_details'][0]['vulnerabilities']), 6)

    def test_generate_dependencies_report_with_empty_dep(self):
        analyzer = EmptyVulnArrayAnalyzer()
        report = analyzer.generate_dependencies_report('test_image_name', [])
        self.assertEqual(len(report['dependencies_details']['java']), 0)
        self.assertEqual(len(report['dependencies_details']['python']), 0)
        self.assertEqual(len(report['dependencies_details']['nodejs']), 0)
        self.assertEqual(len(report['dependencies_details']['js']), 0)
        self.assertEqual(len(report['dependencies_details']['ruby']), 0)
        self.assertEqual(len(report['dependencies_details']['php']), 0)
        self.assertEqual(report['vuln_dependencies'], 0)

    def test_generate_dependencies_report_with_NOT_empty_dep(self):
        analyzer = NotEmptyVulnArrayAnalyzer()
        report = analyzer.generate_dependencies_report('test_image_name', ['java#java#1.5','python#python#2.7'])
        self.assertEqual(len(report['dependencies_details']['java']), 1)
        self.assertEqual(report['dependencies_details']['java'][0]['product'], 'java')
        self.assertEqual(report['dependencies_details']['java'][0]['version'], '1.5')
        self.assertEqual(len(report['dependencies_details']['java'][0]['vulnerabilities']), 6)
        self.assertEqual(len(report['dependencies_details']['python']), 1)
        self.assertEqual(report['dependencies_details']['python'][0]['product'], 'python')
        self.assertEqual(report['dependencies_details']['python'][0]['version'], '2.7')
        self.assertEqual(len(report['dependencies_details']['python'][0]['vulnerabilities']), 6)
        self.assertEqual(len(report['dependencies_details']['nodejs']), 0)
        self.assertEqual(len(report['dependencies_details']['js']), 0)
        self.assertEqual(len(report['dependencies_details']['ruby']), 0)
        self.assertEqual(len(report['dependencies_details']['php']), 0)
        self.assertEqual(report['vuln_dependencies'], 2)

    def test_generate_dependencies_report_with_NOT_empty_dep_with_fp(self):
        analyzer = NotEmptyVulnArrayWithFalsePositivesAnalyzer()
        report = analyzer.generate_dependencies_report('test_image_name', ['java#java#1.5','python#python#2.7'])
        self.assertEqual(len(report['dependencies_details']['java']), 1)
        self.assertEqual(report['dependencies_details']['java'][0]['product'], 'java')
        self.assertEqual(report['dependencies_details']['java'][0]['version'], '1.5')
        self.assertEqual(len(report['dependencies_details']['java'][0]['vulnerabilities']), 6)
        self.assertEqual(len(report['dependencies_details']['python']), 1)
        self.assertEqual(report['dependencies_details']['python'][0]['product'], 'python')
        self.assertEqual(report['dependencies_details']['python'][0]['version'], '2.7')
        self.assertEqual(len(report['dependencies_details']['python'][0]['vulnerabilities']), 6)
        self.assertEqual(len(report['dependencies_details']['nodejs']), 0)
        self.assertEqual(len(report['dependencies_details']['js']), 0)
        self.assertEqual(len(report['dependencies_details']['ruby']), 0)
        self.assertEqual(len(report['dependencies_details']['php']), 0)
        self.assertEqual(report['vuln_dependencies'], 0)


# -- Mock classes

class EmptyVulnArrayAnalyzer(Analyzer):
    def __init__(self):
        self.mongoDbDriver = Mock()
        self.dockerDriver = Mock()
        self.mongoDbDriver.get_vulnerabilities.return_value = []

class NotEmptyVulnArrayAnalyzer(Analyzer):
    def __init__(self):
        self.mongoDbDriver = Mock()
        self.dockerDriver = Mock()
        self.mongoDbDriver.get_vulnerabilities.return_value = ['CVE-2002-2001', 'CVE-2002-2002', 'BID-1', 'BID-2',
                                                               'EXPLOIT_DB_ID-3', 'EXPLOIT_DB_ID-4']
        self.mongoDbDriver.is_fp.return_value = False

class NotEmptyVulnArrayWithFalsePositivesAnalyzer(Analyzer):
    def __init__(self):
        self.mongoDbDriver = Mock()
        self.dockerDriver = Mock()
        self.mongoDbDriver.get_vulnerabilities.return_value = ['CVE-2002-2001', 'CVE-2002-2002', 'BID-1', 'BID-2',
                                                               'EXPLOIT_DB_ID-3', 'EXPLOIT_DB_ID-4']
        self.mongoDbDriver.is_fp.return_value = True


if __name__ == '__main__':
    unittest.main()
