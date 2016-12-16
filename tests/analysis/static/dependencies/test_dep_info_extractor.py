import unittest
import json

from dagda.analysis.static.dependencies.dep_info_extractor import get_filtered_dependencies_info
from dagda.analysis.static.dependencies.dep_info_extractor import raw_info_to_json_array


# -- Test suite

class DepInfoExtractorTestSuite(unittest.TestCase):

    def test_empty_raw_info_to_json_array(self):
        json_array = raw_info_to_json_array(mock_owasp_dependency_chek_empty_output)
        self.assertEqual(len(json_array), 0)

    def test_raw_info_to_json_array(self):
        json_array = raw_info_to_json_array(mock_owasp_dependency_chek_output)
        self.assertEqual(len(json_array), 4)
        self.assertEqual(json_array[0]['cve_type'], 'python')
        self.assertEqual(json_array[1]['cve_type'], 'java')
        self.assertEqual(json_array[2]['cve_type'], 'java')
        self.assertEqual(json_array[3]['cve_type'], 'java')
        self.assertEqual(json_array[0]['cve_caused_by_package'], 'cpe:/a:lxml:lxml:1.0.1')
        self.assertEqual(json_array[1]['cve_caused_by_package'], 'cpe:/a:apache:cxf:2.6.0')
        self.assertEqual(json_array[2]['cve_caused_by_package'], 'cpe:/a:sun:java')
        self.assertEqual(json_array[3]['cve_caused_by_package'], 'cpe:/a:netscape:navigator:4.08')

    def test_raw_info_to_json_array(self):
        filtered_dep = get_filtered_dependencies_info(json.loads(mock_json_array))
        self.assertEqual(len(filtered_dep), 3)
        self.assertTrue('python#lxml#1.0.1' in filtered_dep)
        self.assertTrue('java#cxf#2.6.0' in filtered_dep)
        self.assertTrue('java#navigator#4.08' in filtered_dep)


# -- Mock Constants

mock_json_array = '[{"cve_type": "python", "cve_caused_by_package": "cpe:/a:lxml:lxml:1.0.1"}, {"cve_type": "java", "cve_caused_by_package": "cpe:/a:apache:cxf:2.6.0"}, {"cve_type": "java", "cve_caused_by_package": "cpe:/a:sun:java"}, {"cve_type": "java", "cve_caused_by_package": "cpe:/a:netscape:navigator:4.08"}, {"cve_type": "java", "cve_caused_by_package": "allPriorVersions"}]'

mock_owasp_dependency_chek_empty_output = '''
# ------------------------------------------------------------------------------
# OWASP Dependency Check for Container Images, v 0.1
# Running with following config
#
# Container image               = mongo
# Scan type                     = all
# Proxy                         = none
# Debug messages logged to      = stdout
# Vulnerabilities logged to     = stderr, /tmp/depcheck/mongo
# DB update                     = false
# Databases stored at           = /tmp/dependency-check, /tmp/.retire-cache
# JSON pretty printing          = true
# ------------------------------------------------------------------------------

[INFO] Retirejs is building initial database
[INFO] Saving mongo
[INFO] Getting image history
[INFO] Image mongo has 9 layers which need scanning
[INFO] Cleaning up
[INFO] Done
'''

mock_owasp_dependency_chek_output = '''
# ------------------------------------------------------------------------------
# OWASP Dependency Check for Container Images, v 0.1
# Running with following config
#
# Container image               = jboss/wildfly
# Scan type                     = all
# Proxy                         = none
# Debug messages logged to      = stdout
# Vulnerabilities logged to     = stderr, /tmp/depcheck/jboss_wildfly
# DB update                     = false
# Databases stored at           = /tmp/dependency-check, /tmp/.retire-cache
# JSON pretty printing          = true
# ------------------------------------------------------------------------------

[INFO] OWASP Dependency Check is building initial database
[INFO] Retirejs is building initial database
[INFO] Saving jboss/wildfly
[INFO] Getting image history
[INFO] Image jboss/wildfly has 5 layers which need scanning
{
  "cve_id": "CVE-2014-3146",
  "cve_type": "python",
  "cve_container_image": "jboss/wildfly",
  "cve_severity": "medium",
  "cve_caused_by_package": "cpe:/a:lxml:lxml:1.0.1",
  "cve_container_layer": "d8638866ca75afc334ad1fc4d61e8f1affa27e44cf43859b2d350685a1898034",
  "cve_fixed_in": "Unknown",
  "cve_link": "Unknown",
  "cve_description": "Incomplete blacklist vulnerability in the lxml.html.clean module in lxml before 3.3.5 allows remote attackers to conduct cross-site scripting (XSS) attacks via control characters in the link scheme to the clean_html function.",
  "cve_cvss_score": "4.30",
  "cve_attack_vector": "NETWORK"
}
{
  "cve_id": "CVE-2012-5786",
  "cve_type": "java",
  "cve_container_image": "jboss/wildfly",
  "cve_severity": "medium",
  "cve_caused_by_package": "cpe:/a:apache:cxf:2.6.0",
  "cve_container_layer": "08978a0d401024b416d94eb19b22604c4358c2b0b88f70326a345cea043a632c",
  "cve_fixed_in": "Unknown",
  "cve_link": "Unknown",
  "cve_description": "The wsdl_first_https sample code in distribution/src/main/release/samples/wsdl_first_https/src/main/ in Apache CXF, possibly 2.6.0, does not verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via an arbitrary valid certificate.",
  "cve_cvss_score": "5.80",
  "cve_attack_vector": "NETWORK"
}
{
  "cve_id": "CVE-2009-1103",
  [INFO] Cleaning up
[INFO] Done
  "cve_type": "java",
  "cve_container_image": "jboss/wildfly",
  "cve_severity": "medium",
  "cve_caused_by_package": "cpe:/a:sun:java",
  "cve_container_layer": "96b48efbef4027cb94dae17123fda6e0d0099f208e9736d95292f5327799f47e",
  "cve_fixed_in": "Unknown",
  "cve_link": "Unknown",
  "cve_description": "Unspecified vulnerability in the Java Plug-in in Java SE Development Kit (JDK) and Java Runtime Environment (JRE) 5.0 Update 17 and earlier 6 Update 12 and earlier 1.4.2_19 and earlier and 1.3.1_24 and earlier allows remote attackers to access files and execute arbitrary code via unknown vectors related to 'deserializing applets,' aka CR 6646860.",
  "cve_cvss_score": "6.40",
  "cve_attack_vector": "NETWORK"
}
{
  "cve_id": "CVE-1999-0440",
  "cve_type": "java",
  "cve_container_image": "jboss/wildfly",
  "cve_severity": "high",
  "cve_caused_by_package": "cpe:/a:netscape:navigator:4.08",
  "cve_container_layer": "96b48efbef4027cb94dae17123fda6e0d0099f208e9736d95292f5327799f47e",
  "cve_fixed_in": "Unknown",
  "cve_link": "Unknown",
  "cve_description": "The byte code verifier component of the Java Virtual Machine (JVM) allows remote execution through malicious web pages.",
  "cve_cvss_score": "7.50",
  "cve_attack_vector": "NETWORK"
}
'''


if __name__ == '__main__':
    unittest.main()
