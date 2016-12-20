import unittest
from unittest.mock import Mock

import sys, os
sys.path.insert(1, str(os.path.dirname(os.path.abspath(__file__))) + '/../../dagda')
from analysis.analyzer import Analyzer


# -- Test suite

class AnalyzerTestCase(unittest.TestCase):

    def test_generate_os_report_with_empty_dep(self):
        analyzer = EmptyVulnArrayAnalyzer()
        report = analyzer.generate_os_report([])
        self.assertEqual(report['total_os_packages'], 0)
        self.assertEqual(report['vuln_os_packages'], 0)
        self.assertEqual(report['ok_os_packages'], 0)
        self.assertEqual(len(report['os_packages_details']), 0)

    def test_generate_os_report_with_NOT_empty_dep(self):
        analyzer = NotEmptyVulnArrayAnalyzer()
        report = analyzer.generate_os_report([{'product': 'java', 'version': '1.5'}])
        self.assertEqual(report['total_os_packages'], 1)
        self.assertEqual(report['vuln_os_packages'], 1)
        self.assertEqual(report['ok_os_packages'], 0)
        self.assertEqual(len(report['os_packages_details']), 1)
        self.assertEqual(report['os_packages_details'][0]['product'], 'java')
        self.assertEqual(report['os_packages_details'][0]['version'], '1.5')
        self.assertEqual(len(report['os_packages_details'][0]['vulnerabilities']), 6)

    def test_generate_dependencies_report_with_empty_dep(self):
        analyzer = EmptyVulnArrayAnalyzer()
        report = analyzer.generate_dependencies_report([])
        self.assertEqual(len(report['dependencies_details']['java']), 0)
        self.assertEqual(len(report['dependencies_details']['python']), 0)
        self.assertEqual(len(report['dependencies_details']['nodejs']), 0)
        self.assertEqual(len(report['dependencies_details']['js']), 0)
        self.assertEqual(len(report['dependencies_details']['ruby']), 0)
        self.assertEqual(len(report['dependencies_details']['php']), 0)
        self.assertEqual(report['vuln_dependencies'], 0)

    def test_generate_dependencies_report_with_NOT_empty_dep(self):
        analyzer = NotEmptyVulnArrayAnalyzer()
        report = analyzer.generate_dependencies_report(['java#java#1.5','python#python#2.7'])
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


if __name__ == '__main__':
    unittest.main()
