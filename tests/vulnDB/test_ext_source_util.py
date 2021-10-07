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
import base64
import io
import datetime
from dagda.vulnDB.ext_source_util import get_cve_list_from_file
from dagda.vulnDB.ext_source_util import get_exploit_db_list_from_csv
from dagda.vulnDB.ext_source_util import get_bug_traqs_lists_from_file
from dagda.vulnDB.ext_source_util import get_bug_traqs_lists_from_online_mode
from dagda.vulnDB.ext_source_util import get_rhsa_and_rhba_lists_from_file


# -- Test suite

class ExtSourceUtilTestCase(unittest.TestCase):

    def test_get_rhsa_from_file(self):
        content = None
        with open('./tests/mock_files/com.redhat.rhsa-2010.xml.bz2', 'rb') as content_file:
            content = content_file.read()
        rhsa_list, rhba_list, rhsa_info_list, rhba_info_list = get_rhsa_and_rhba_lists_from_file(content)
        self.assertEqual(len(rhsa_list), 384)
        self.assertEqual(len(rhba_list), 0)
        self.assertEqual(len(rhsa_info_list), 251)
        self.assertEqual(len(rhba_info_list), 0)
        self.assertEqual(rhsa_list[0], {'product': 'enterprise_linux', 'vendor': 'redhat', 'rhsa_id': 'RHSA-2010:0002', 'version': '4'})
        self.assertEqual(rhsa_info_list[0], {'severity': 'Moderate', 'rhsa_id': 'RHSA-2010:0002', 'title': 'RHSA-2010:0002: PyXML security update (Moderate)', 'cve': ['CVE-2009-3720'], 'description': "PyXML provides XML libraries for Python. The distribution contains a\nvalidating XML parser, an implementation of the SAX and DOM programming\ninterfaces, and an interface to the Expat parser.\n\nA buffer over-read flaw was found in the way PyXML's Expat parser handled\nmalformed UTF-8 sequences when processing XML files. A specially-crafted\nXML file could cause Python applications using PyXML's Expat parser to\ncrash while parsing the file. (CVE-2009-3720)\n\nThis update makes PyXML use the system Expat library rather than its own\ninternal copy; therefore, users must install the RHSA-2009:1625 expat\nupdate together with this PyXML update to resolve the CVE-2009-3720 issue.\n\nAll PyXML users should upgrade to this updated package, which changes PyXML\nto use the system Expat library. After installing this update along with\nRHSA-2009:1625, applications using the PyXML library must be restarted for\nthe update to take effect."})

    def test_get_rhba_from_file(self):
        content = None
        with open('./tests/mock_files/com.redhat.rhba-20171767.xml.bz2', 'rb') as content_file:
            content = content_file.read()
        rhsa_list, rhba_list, rhsa_info_list, rhba_info_list = get_rhsa_and_rhba_lists_from_file(content)
        self.assertEqual(len(rhsa_list), 0)
        self.assertEqual(len(rhba_list), 1)
        self.assertEqual(len(rhsa_info_list), 0)
        self.assertEqual(len(rhba_info_list), 1)
        self.assertEqual(rhba_list[0], {'version': '7', 'product': 'enterprise_linux', 'rhba_id': 'RHBA-2017:1767', 'vendor': 'redhat'})
        self.assertEqual(rhba_info_list[0], {'description': 'The Berkeley Internet Name Domain (BIND) is an implementation of the Domain Name System (DNS) protocols. BIND includes a DNS server (named); a resolver library (routines for applications to use when interfacing with DNS); and tools for verifying that the DNS server is operating correctly.\n\nFor detailed information on changes in this release, see the Red Hat Enterprise Linux 7.4 Release Notes linked from the References section.\n\nUsers of bind are advised to upgrade to these updated packages.', 'rhba_id': 'RHBA-2017:1767', 'cve': ['CVE-2016-2775'], 'severity': 'None', 'title': 'RHBA-2017:1767: bind bug fix update (None)'})

    def test_get_exploit_db_list_from_csv(self):
        exploit_db_list, exploit_db_info_list = get_exploit_db_list_from_csv(mock_exploit_db_csv_content)
        self.assertEqual(len(exploit_db_list), 3)
        self.assertEqual(len(exploit_db_info_list), 3)
        # Check Exploits
        self.assertTrue("11#apache#2.0.44" in exploit_db_list)
        self.assertTrue("468#pigeon server#3.02.0143" in exploit_db_list)
        self.assertTrue("37060#microsoft internet explorer#11" in exploit_db_list)

    def test_get_bug_traqs_lists_from_file(self):
        output = io.BytesIO(base64.b64decode(mock_bid_gz_file))
        bid_lists, bid_info_list = get_bug_traqs_lists_from_file(output)
        self.assertEqual(len(bid_lists), 1)
        self.assertEqual(len(bid_lists[0]), 7)
        self.assertEqual(len(bid_info_list), 4)
        # Check BugTraqs
        self.assertTrue("1#eric allman sendmail#5.58" in bid_lists[0])
        self.assertTrue("3#sun sunos#4.0.1" in bid_lists[0])
        self.assertTrue("4#bsd bsd#4.3" in bid_lists[0])
        # Check BugTraq Details
        self.assertEqual(bid_info_list[1], {"bugtraq_id": 2, "title": "BSD fingerd buffer overflow Vulnerability", "class": "Boundary Condition Error", "cve": [], "local": "no", "remote": "yes"})

    def test_get_bug_traqs_lists_from_online_mode(self):
        bid_lists, bid_info_list = get_bug_traqs_lists_from_online_mode(mock_bid_online_mode)
        self.assertEqual(len(bid_lists), 1)
        self.assertEqual(len(bid_lists[0]), 7)
        self.assertEqual(len(bid_info_list), 4)
        # Check BugTraqs
        self.assertTrue("1#eric allman sendmail#5.58" in bid_lists[0])
        self.assertTrue("3#sun sunos#4.0.1" in bid_lists[0])
        self.assertTrue("4#bsd bsd#4.3" in bid_lists[0])
        # Check BugTraq Details
        self.assertEqual(bid_info_list[0], {"bugtraq_id": 1, "title": "Berkeley Sendmail DEBUG Vulnerability", "class": "Configuration Error", "cve": [], "local": "yes", "remote": "yes"})


# -- Mock Constants
mock_cve_info_set = {}
mock_cve_info_set['CVE-2016-0002'] = {'cveid': 'CVE-2016-0002',
                                      'cvss_access_complexity': 'High',
                                      'cvss_access_vector': 'Network',
                                      'cvss_authentication': 'None required',
                                      'cvss_availability_impact': 'Complete',
                                      'cvss_base': 7.6,
                                      'cvss_confidentiality_impact': 'Complete',
                                      'cvss_exploit': 4.9,
                                      'cvss_impact': 10.0,
                                      'cvss_integrity_impact': 'Complete',
                                      'cvss_vector': ['AV:N', 'AC:H', 'Au:N', 'C:C', 'I:C', 'A:C'],
                                      'cweid': 'CWE-119',
                                      'mod_date': datetime.datetime(2016, 12, 7, 0, 0),
                                      'pub_date': datetime.datetime(2016, 1, 13, 0, 0),
                                      'summary': 'The Microsoft (1) VBScript 5.7 and 5.8 and (2) JScript 5.7 and 5.8 engines, as used in Internet Explorer 8 through 11 and other products, allow remote attackers to execute arbitrary code via a crafted web site, aka "Scripting Engine Memory Corruption Vulnerability."'}
mock_cve_info_set['CVE-2016-0005'] = {'cveid': 'CVE-2016-0005',
                                      'cvss_access_complexity': 'Medium',
                                      'cvss_access_vector': 'Network',
                                      'cvss_authentication': 'None required',
                                      'cvss_availability_impact': 'None',
                                      'cvss_base': 4.3,
                                      'cvss_confidentiality_impact': 'None',
                                      'cvss_exploit': 8.6,
                                      'cvss_impact': 2.9,
                                      'cvss_integrity_impact': 'Partial',
                                      'cvss_vector': ['AV:N', 'AC:M', 'Au:N', 'C:N', 'I:P', 'A:N'],
                                      'cweid': 'CWE-20',
                                      'mod_date': datetime.datetime.now().strftime('%d-%m-%Y'),
                                      'pub_date': datetime.datetime.now().strftime('%d-%m-%Y'),
                                      'summary': 'Microsoft Internet Explorer 9 through 11 allows remote attackers to bypass the Same Origin Policy via unspecified vectors, aka "Internet Explorer Elevation of Privilege Vulnerability."'}
mock_cve_info_set['CVE-2016-0006'] = {'cveid': 'CVE-2016-0006',
                                      'cvss_access_complexity': 'Medium',
                                      'cvss_access_vector': 'Local access',
                                      'cvss_authentication': 'None required',
                                      'cvss_availability_impact': 'Complete',
                                      'cvss_base': 6.9,
                                      'cvss_confidentiality_impact': 'Complete',
                                      'cvss_exploit': 3.4,
                                      'cvss_impact': 10.0,
                                      'cvss_integrity_impact': 'Complete',
                                      'cvss_vector': ['AV:L', 'AC:M', 'Au:N', 'C:C', 'I:C', 'A:C'],
                                      'cweid': 'CWE-264',
                                      'mod_date': datetime.datetime(2016, 12, 7, 0, 0),
                                      'pub_date': datetime.datetime(2016, 1, 13, 0, 0),
                                      'summary': 'The sandbox implementation in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT Gold and 8.1, and Windows 10 Gold and 1511 mishandles reparse points, which allows local users to gain privileges via a crafted application, aka "Windows Mount Point Elevation of Privilege Vulnerability," a different vulnerability than CVE-2016-0007.'}

mock_exploit_db_csv_content = """"
id,file,description,date,author,type,platform,port
262,platforms/hardware/dos/262.pl,"Cisco Multiple Products - Automated Exploit Tool",2001-01-27,hypoclear,dos,hardware,0
11,platforms/linux/dos/11.c,"Apache 2.0.44 (Linux) - Remote Denial of Service",2003-04-11,"Daniel Nystram",dos,linux,0
345,platforms/windows/dos/345.c,"UDP Stress Tester - Denial of Service",2002-09-10,Cys,dos,windows,0
37060,platforms/windows/dos/37060.html,"Microsoft Internet Explorer 11 - Crash PoC (1)",2015-05-19,Garage4Hackers,dos,windows,0
468,platforms/windows/dos/468.c,"Pigeon Server 3.02.0143 - Denial of Service",2004-09-19,"Luigi Auriemma",dos,windows,0
"""

mock_bid_gz_file = 'H4sICLIHFlkAA2ZvcnRlc3RpbmcArZE9b8IwEIb3/oqT5xI1ENSmW4GoY4cIFoSQk1wiC2PTi00Uof732jBA+CpDh5NO9/m8dzuW2coQ/16Kgr1D+AzMCCPR+WyEtEKJLaSoijUXEibJaPoJMysVEs+EFKZlriOXvK59x1irUlSWuBFaQUKkaZ/f+nnzhXOlzrn0pS3WPkW41gZPAls3fLkhXdjc+JlzlpDI4UPKNVdHkmEwfGOLn6ddl7/f4U8nUApVIRWQ2bJEAr1FKqVu7mgYaasKTi04MYX4W4jSD+rwON6ioH+FfHBKnlr1lQJhbTThHdapWindqIdvfGC9RHP74LAzCl6CgS/qhsKL0BUJ0fnxNw6z+efbs/Es6YVxHPfC6DVkd19xS+7xE3upZ4/5BeMbMzkTAwAA'

mock_bid_online_mode = ['{"bugtraq_id": 1, "title": "Berkeley Sendmail DEBUG Vulnerability", "class": "Configuration Error", "cve": [], "local": "yes", "remote": "yes", "vuln_products": ["Eric Allman Sendmail 5.58"]}','{"bugtraq_id": 2, "title": "BSD fingerd buffer overflow Vulnerability", "class": "Boundary Condition Error", "cve": [], "local": "no", "remote": "yes", "vuln_products": ["BSD BSD 4.2"]}','{"bugtraq_id": 3, "title": "SunOS restore Vulnerability", "class": "Unknown", "cve": [], "local": "yes", "remote": "no", "vuln_products": ["Sun SunOS 4.0.3", "Sun SunOS 4.0.1", "Sun SunOS 4.0"]}','{"bugtraq_id": 4, "title": "BSD passwd buffer overflow Vulnerability", "class": "Boundary Condition Error", "cve": ["CVE-1999-1471"], "local": "no", "remote": "no", "vuln_products": ["BSD BSD 4.3", "BSD BSD 4.2"]}']

if __name__ == '__main__':
    unittest.main()
