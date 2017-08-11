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

import pymongo
import datetime

from dagda.driver.mongodb_driver import MongoDbDriver

import pytest


# -- Test suite

class MongoDbDriverTestCase(unittest.TestCase):

    def test_get_vulnerabilities_product_full_happy_path(self):
        mock_driver = FullGetVulnProdMongoDbDriver()
        vulnerabilities = mock_driver.get_vulnerabilities('openldap')
        self.assertEqual(len(vulnerabilities), 6)
        self.assertDictEqual(vulnerabilities[0],{"CVE-2002-2001":{"cvss_access_vector": "Network",
                                               "cveid": "CVE-2002-2002",
                                               "cvss_base": 7.5,
                                               "cvss_integrity_impact": "Partial",
                                               "cvss_availability_impact": "Partial",
                                               "summary": "Summary example",
                                               "cvss_confidentiality_impact": "Partial",
                                               "cvss_vector": ["AV:N","AC:L","Au:N","C:P","I:P","A:P"],
                                               "cvss_authentication": "None required",
                                               "cvss_access_complexity": "Low",
                                               "pub_date": datetime.datetime.now().strftime('%d-%m-%Y'),
                                               "cvss_impact": 6.4,
                                               "cvss_exploit": 10.0,
                                               "mod_date": datetime.datetime.now().strftime('%d-%m-%Y'),
                                               "cweid": "CWE-0"
                                               }})
        self.assertDictEqual(vulnerabilities[1],{"CVE-2002-2002":{"cvss_access_vector": "Network",
                                                   "cveid": "CVE-2002-2002",
                                                   "cvss_base": 7.5,
                                                   "cvss_integrity_impact": "Partial",
                                                   "cvss_availability_impact": "Partial",
                                                   "summary": "Summary example",
                                                   "cvss_confidentiality_impact": "Partial",
                                                   "cvss_vector": ["AV:N","AC:L","Au:N","C:P","I:P","A:P"],
                                                   "cvss_authentication": "None required",
                                                   "cvss_access_complexity": "Low",
                                                   "pub_date": datetime.datetime.now().strftime('%d-%m-%Y'),
                                                   "cvss_impact": 6.4,
                                                   "cvss_exploit": 10.0,
                                                   "mod_date": datetime.datetime.now().strftime('%d-%m-%Y'),
                                                   "cweid": "CWE-0"
                                                   }})

        self.assertDictEqual(vulnerabilities[2],{"BID-1": {
                                                    "bugtraq_id": 15128,
                                                    "class": "Boundary Condition Error",
                                                    "cve": [
                                                        "CVE-2005-2978"
                                                    ],
                                                    "local": "no",
                                                    "remote": "yes",
                                                    "title": "NetPBM PNMToPNG Buffer Overflow Vulnerability"
                                                }})
        self.assertDictEqual(vulnerabilities[3],{"BID-2": {
                                                    "bugtraq_id": 15128,
                                                    "class": "Boundary Condition Error",
                                                    "cve": [
                                                        "CVE-2005-2978"
                                                    ],
                                                    "local": "no",
                                                    "remote": "yes",
                                                    "title": "NetPBM PNMToPNG Buffer Overflow Vulnerability"
                                                }})
        self.assertDictEqual(vulnerabilities[4],{"EXPLOIT_DB_ID-3": {'exploit_db_id': 1,
                                                                     'description': 'Summary example',
                                                                     'platform': 'Linux',
                                                                     'type': 'DoS',
                                                                     'port': 0
                                                                    }})
        self.assertDictEqual(vulnerabilities[5],{"EXPLOIT_DB_ID-4": {'exploit_db_id': 1,
                                                                     'description': 'Summary example',
                                                                     'platform': 'Linux',
                                                                     'type': 'DoS',
                                                                     'port': 0
                                                                    }})

    def test_get_vulnerabilities_product_and_version_full_happy_path(self):
        mock_driver = FullGetVulnProdAndVersionMongoDbDriver()
        vulnerabilities = mock_driver.get_vulnerabilities('openldap','2.2.20')
        self.assertEqual(len(vulnerabilities), 6)
        self.assertDictEqual(vulnerabilities[0],{"CVE-2005-4442":{"cvss_access_vector": "Network",
                                                   "cveid": "CVE-2005-4442",
                                                   "cvss_base": 7.5,
                                                   "cvss_integrity_impact": "Partial",
                                                   "cvss_availability_impact": "Partial",
                                                   "summary": "Summary example",
                                                   "cvss_confidentiality_impact": "Partial",
                                                   "cvss_vector": ["AV:N","AC:L","Au:N","C:P","I:P","A:P"],
                                                   "cvss_authentication": "None required",
                                                   "cvss_access_complexity": "Low",
                                                   "pub_date": datetime.datetime.now().strftime('%d-%m-%Y'),
                                                   "cvss_impact": 6.4,
                                                   "cvss_exploit": 10.0,
                                                   "mod_date": datetime.datetime.now().strftime('%d-%m-%Y'),
                                                   "cweid": "CWE-0"
                                                   }})
        self.assertDictEqual(vulnerabilities[1],{"CVE-2006-2754":{"cvss_access_vector": "Network",
                                               "cveid": "CVE-2005-4442",
                                               "cvss_base": 7.5,
                                               "cvss_integrity_impact": "Partial",
                                               "cvss_availability_impact": "Partial",
                                               "summary": "Summary example",
                                               "cvss_confidentiality_impact": "Partial",
                                               "cvss_vector": ["AV:N","AC:L","Au:N","C:P","I:P","A:P"],
                                               "cvss_authentication": "None required",
                                               "cvss_access_complexity": "Low",
                                               "pub_date": datetime.datetime.now().strftime('%d-%m-%Y'),
                                               "cvss_impact": 6.4,
                                               "cvss_exploit": 10.0,
                                               "mod_date": datetime.datetime.now().strftime('%d-%m-%Y'),
                                               "cweid": "CWE-0"
                                               }})
        self.assertDictEqual(vulnerabilities[2],{"CVE-2007-5707":{"cvss_access_vector": "Network",
                                               "cveid": "CVE-2005-4442",
                                               "cvss_base": 7.5,
                                               "cvss_integrity_impact": "Partial",
                                               "cvss_availability_impact": "Partial",
                                               "summary": "Summary example",
                                               "cvss_confidentiality_impact": "Partial",
                                               "cvss_vector": ["AV:N","AC:L","Au:N","C:P","I:P","A:P"],
                                               "cvss_authentication": "None required",
                                               "cvss_access_complexity": "Low",
                                               "pub_date": datetime.datetime.now().strftime('%d-%m-%Y'),
                                               "cvss_impact": 6.4,
                                               "cvss_exploit": 10.0,
                                               "mod_date": datetime.datetime.now().strftime('%d-%m-%Y'),
                                               "cweid": "CWE-0"
                                               }})
        self.assertDictEqual(vulnerabilities[3],{"CVE-2011-4079":{"cvss_access_vector": "Network",
                                             "cveid": "CVE-2005-4442",
                                             "cvss_base": 7.5,
                                             "cvss_integrity_impact": "Partial",
                                             "cvss_availability_impact": "Partial",
                                             "summary": "Summary example",
                                             "cvss_confidentiality_impact": "Partial",
                                             "cvss_vector": ["AV:N","AC:L","Au:N","C:P","I:P","A:P"],
                                             "cvss_authentication": "None required",
                                             "cvss_access_complexity": "Low",
                                             "pub_date": datetime.datetime.now().strftime('%d-%m-%Y'),
                                             "cvss_impact": 6.4,
                                             "cvss_exploit": 10.0,
                                             "mod_date": datetime.datetime.now().strftime('%d-%m-%Y'),
                                             "cweid": "CWE-0"
                                             }})
        self.assertDictEqual(vulnerabilities[4],{"BID-83610": {
                                                    "bugtraq_id": 15128,
                                                    "class": "Boundary Condition Error",
                                                    "cve": [
                                                        "CVE-2005-2978"
                                                    ],
                                                    "local": "no",
                                                    "remote": "yes",
                                                    "title": "NetPBM PNMToPNG Buffer Overflow Vulnerability"
                                                }})
        self.assertDictEqual(vulnerabilities[5],{"BID-83843": {
                                                    "bugtraq_id": 15128,
                                                    "class": "Boundary Condition Error",
                                                    "cve": [
                                                        "CVE-2005-2978"
                                                    ],
                                                    "local": "no",
                                                    "remote": "yes",
                                                    "title": "NetPBM PNMToPNG Buffer Overflow Vulnerability"
                                                }})

    def test_bulk_insert_cves(self):
        mock_driver = BulkInfoMongoDbDriver()
        mock_driver.bulk_insert_cves(["CVE-2002-2001#Vendor 1#Product 1#1.1.0#2001",
                                      "CVE-2002-2002#Vendor 2#Product 2#2.1.1#2002"])
        mock_driver.db.cve.insert_many.assert_called_once_with([
            {'cve_id': 'CVE-2002-2001', 'vendor': 'Vendor 1',
             'product': 'Product 1', 'version': '1.1.0', 'year': 2001},
            {'cve_id': 'CVE-2002-2002', 'vendor': 'Vendor 2',
             'product': 'Product 2', 'version': '2.1.1', 'year': 2002}])

    def test_bulk_insert_bids(self):
        mock_driver = BulkInfoMongoDbDriver()
        mock_driver.bulk_insert_bids(["1#Product 1#1.1.0", "2#Product 2#2.1.1"])
        mock_driver.db.bid.insert_many.assert_called_once_with([
            {'bugtraq_id': 1, 'product': 'Product 1', 'version': '1.1.0'},
            {'bugtraq_id': 2, 'product': 'Product 2', 'version': '2.1.1'}])

    def test_bulk_insert_exploit_db_ids(self):
        mock_driver = BulkInfoMongoDbDriver()
        mock_driver.bulk_insert_exploit_db_ids(["1#Product 1#1.1.0", "2#Product 2#2.1.1"])
        mock_driver.db.exploit_db.insert_many.assert_called_once_with([
            {'exploit_db_id': 1, 'product': 'Product 1', 'version': '1.1.0'},
            {'exploit_db_id': 2, 'product': 'Product 2', 'version': '2.1.1'}])

    def test_bulk_insert_sysdig_falco_events(self):
        mock_driver = BulkInfoMongoDbDriver()
        mock_driver.bulk_insert_sysdig_falco_events([{"container_id": "ef45au6756jh", "image_name": "alpine",
            "output": "16:47:44.080226697: Warning Sensitive file opened for reading by non-trusted program (user=root command=cat /etc/shadow file=/etc/shadow)",
            "priority": "Warning",
            "rule": "read_sensitive_file_untrusted",
            "time": "2016-06-06T23:47:44.080226697Z"
        }])
        mock_driver.db.falco_events.insert_many.assert_called_once_with([{"container_id": "ef45au6756jh",
                                                                          "image_name": "alpine",
            "output": "16:47:44.080226697: Warning Sensitive file opened for reading by non-trusted program (user=root command=cat /etc/shadow file=/etc/shadow)",
            "priority": "Warning",
            "rule": "read_sensitive_file_untrusted",
            "time": 1465256864.080226
        }])

    def test_is_fp_false(self):
        mock_driver = IsFPMongoDbDriver()
        is_fp = mock_driver.is_fp('alpine', 'zlib')
        self.assertFalse(is_fp)

    def test_is_fp_true(self):
        mock_driver = IsFPMongoDbDriver()
        is_fp = mock_driver.is_fp('alpine', 'musl', '1.1.15')
        self.assertTrue(is_fp)

    def test_update_fp(self):
        mock_driver = UpdateFPMongoDbDriver()
        updated = mock_driver.update_product_vulnerability_as_fp('alpine', 'musl', '1.1.15')
        self.assertTrue(updated)
        mock_driver.db.image_history.update.assert_called_once_with({'_id': "5915ed36ff1f081833551af5"},
                                                             {"_id": "5915ed36ff1f081833551af5",
                                                              "timestamp": 1494609523.342605, "status": "Completed",
                                                              "image_name": "alpine",
                                                              "static_analysis": {"prog_lang_dependencies": {
                                                                  "dependencies_details": {"java": [], "python": [],
                                                                                           "js": [], "ruby": [],
                                                                                           "php": [], "nodejs": []},
                                                                  "vuln_dependencies": 0},
                                                                  "os_packages": {"vuln_os_packages": 1,
                                                                                  "os_packages_details": [
                                                                                      {"version": "1.1.15",
                                                                                       "vulnerabilities": [{
                                                                                                               "CVE-2016-8859": {
                                                                                                                   "cvss_integrity_impact": "Partial",
                                                                                                                   "cvss_access_vector": "Network",
                                                                                                                   "cweid": "CWE-190",
                                                                                                                   "cvss_access_complexity": "Low",
                                                                                                                   "cvss_confidentiality_impact": "Partial",
                                                                                                                   "mod_date": "07-03-2017",
                                                                                                                   "cvss_exploit": 10,
                                                                                                                   "cvss_vector": [
                                                                                                                       "AV:N",
                                                                                                                       "AC:L",
                                                                                                                       "Au:N",
                                                                                                                       "C:P",
                                                                                                                       "I:P",
                                                                                                                       "A:P"],
                                                                                                                   "cvss_authentication": "None required",
                                                                                                                   "summary": "Multiple integer overflows in the TRE library and musl libc allow attackers to cause memory corruption via a large number of (1) states or (2) tags, which triggers an out-of-bounds write.",
                                                                                                                   "cveid": "CVE-2016-8859",
                                                                                                                   "cvss_impact": 6.4,
                                                                                                                   "pub_date": "13-02-2017",
                                                                                                                   "cvss_base": 7.5,
                                                                                                                   "cvss_availability_impact": "Partial"}}],
                                                                                       "product": "musl",
                                                                                       "is_vulnerable": True,
                                                                                       "is_false_positive": True},
                                                                                      {"version": "1.25.1",
                                                                                       "vulnerabilities": [],
                                                                                       "product": "busybox",
                                                                                       "is_vulnerable": False,
                                                                                       "is_false_positive": False},
                                                                                      {"version": "3.0.4",
                                                                                       "vulnerabilities": [],
                                                                                       "product": "alpine-baselayout",
                                                                                       "is_vulnerable": False,
                                                                                       "is_false_positive": False},
                                                                                      {"version": "1.3",
                                                                                       "vulnerabilities": [],
                                                                                       "product": "alpine-keys",
                                                                                       "is_vulnerable": False,
                                                                                       "is_false_positive": False},
                                                                                      {"version": "2.4.4",
                                                                                       "vulnerabilities": [],
                                                                                       "product": "libressl2.4-libcrypto",
                                                                                       "is_vulnerable": False,
                                                                                       "is_false_positive": False},
                                                                                      {"version": "2.4.4",
                                                                                       "vulnerabilities": [],
                                                                                       "product": "libressl2.4-libssl",
                                                                                       "is_vulnerable": False,
                                                                                       "is_false_positive": False},
                                                                                      {"version": "1.2.8",
                                                                                       "vulnerabilities": [{
                                                                                                               "BID-95131": {
                                                                                                                   "cve": [
                                                                                                                       "CVE-2016-9840"],
                                                                                                                   "bugtraq_id": 95131,
                                                                                                                   "title": "zlib Multiple Denial of Service Vulnerabilities",
                                                                                                                   "remote": "yes",
                                                                                                                   "local": "no",
                                                                                                                   "class": "Design Error"}}],
                                                                                       "product": "zlib",
                                                                                       "is_vulnerable": True,
                                                                                       "is_false_positive": False},
                                                                                      {"version": "2.6.8",
                                                                                       "vulnerabilities": [],
                                                                                       "product": "apk-tools",
                                                                                       "is_vulnerable": False,
                                                                                       "is_false_positive": False},
                                                                                      {"version": "1.1.6",
                                                                                       "vulnerabilities": [],
                                                                                       "product": "scanelf",
                                                                                       "is_vulnerable": False,
                                                                                       "is_false_positive": False},
                                                                                      {"version": "1.1.15",
                                                                                       "vulnerabilities": [],
                                                                                       "product": "musl-utils",
                                                                                       "is_vulnerable": False,
                                                                                       "is_false_positive": False},
                                                                                      {"version": "0.7",
                                                                                       "vulnerabilities": [],
                                                                                       "product": "libc-utils",
                                                                                       "is_vulnerable": False,
                                                                                       "is_false_positive": False}],
                                                                                  "total_os_packages": 11,
                                                                                  "ok_os_packages": 10}}})


# -- Mock classes

class FullGetVulnProdMongoDbDriver(MongoDbDriver):
    def __init__(self):
        self.client = Mock(spec=pymongo.MongoClient)
        self.db = Mock()
        cursor_cve = self.db.cve.find.return_value
        cursor_cve.sort.return_value = [{'cve_id': "CVE-2002-2001"}, {'cve_id': "CVE-2002-2002"}]
        cursor_bid = self.db.bid.find.return_value
        cursor_bid.sort.return_value = [{'bugtraq_id': 1}, {'bugtraq_id': 2}]
        cursor_expl = self.db.exploit_db.find.return_value
        cursor_expl.sort.return_value = [{'exploit_db_id': 3}, {'exploit_db_id': 4}]
        self.db.cve_info.find_one.return_value = {"cvss_access_vector": "Network",
                                                  "_id": "58d11025100e75000e789c9a",
                                                  "cveid": "CVE-2002-2002",
                                                  "cvss_base": 7.5,
                                                  "cvss_integrity_impact": "Partial",
                                                  "cvss_availability_impact": "Partial",
                                                  "summary": "Summary example",
                                                  "cvss_confidentiality_impact": "Partial",
                                                  "cvss_vector": [
                                                      "AV:N",
                                                      "AC:L",
                                                      "Au:N",
                                                      "C:P",
                                                      "I:P",
                                                      "A:P"
                                                  ],
                                                  "cvss_authentication": "None required",
                                                  "cvss_access_complexity": "Low",
                                                  "pub_date": datetime.datetime.now(),
                                                  "cvss_impact": 6.4,
                                                  "cvss_exploit": 10.0,
                                                  "mod_date": datetime.datetime.now(),
                                                  "cweid": "CWE-0"
                                                  }
        self.db.exploit_db_info.find_one.return_value = {'_id': '58d11025100e75000e789c9a',
                                                         'exploit_db_id': 1,
                                                         'description': 'Summary example',
                                                         'platform': 'Linux',
                                                         'type': 'DoS',
                                                         'port': 0
                                                        }
        self.db.bid_info.find_one.return_value = {
                                                    "_id": "'58d11025100e75000e789c9a",
                                                    "bugtraq_id": 15128,
                                                    "class": "Boundary Condition Error",
                                                    "cve": [
                                                        "CVE-2005-2978"
                                                    ],
                                                    "local": "no",
                                                    "remote": "yes",
                                                    "title": "NetPBM PNMToPNG Buffer Overflow Vulnerability"
                                                }


class FullGetVulnProdAndVersionMongoDbDriver(MongoDbDriver):
    def __init__(self):
        self.client = Mock(spec=pymongo.MongoClient)
        self.db = Mock()
        cursor_cve = self.db.cve.find.return_value
        cursor_cve.sort.return_value = [{'cve_id': "CVE-2005-4442"}, {'cve_id': "CVE-2006-2754"},
                                        {'cve_id': "CVE-2007-5707"}, {'cve_id': "CVE-2011-4079"}]
        cursor_bid = self.db.bid.find.return_value
        cursor_bid.sort.return_value = [{'bugtraq_id': 83610}, {'bugtraq_id': 83843}]
        cursor_expl = self.db.exploit_db.find.return_value
        cursor_expl.sort.return_value = []
        self.db.cve_info.find_one.return_value = {"cvss_access_vector": "Network",
                                                  "_id": "58d11025100e75000e789c9a",
                                                  "cveid": "CVE-2005-4442",
                                                  "cvss_base": 7.5,
                                                  "cvss_integrity_impact": "Partial",
                                                  "cvss_availability_impact": "Partial",
                                                  "summary": "Summary example",
                                                  "cvss_confidentiality_impact": "Partial",
                                                  "cvss_vector": [
                                                      "AV:N",
                                                      "AC:L",
                                                      "Au:N",
                                                      "C:P",
                                                      "I:P",
                                                      "A:P"
                                                  ],
                                                  "cvss_authentication": "None required",
                                                  "cvss_access_complexity": "Low",
                                                  "pub_date": datetime.datetime.now(),
                                                  "cvss_impact": 6.4,
                                                  "cvss_exploit": 10.0,
                                                  "mod_date": datetime.datetime.now(),
                                                  "cweid": "CWE-0"
                                                  }
        self.db.exploit_db_info.find_one.return_value = {'_id': '58d11025100e75000e789c9a',
                                                         'exploit_db_id': 1,
                                                         'description': 'Summary example',
                                                         'platform': 'Linux',
                                                         'type': 'DoS',
                                                         'port': 0
                                                        }
        self.db.bid_info.find_one.return_value = {
                                                    "_id": "'58d11025100e75000e789c9a",
                                                    "bugtraq_id": 15128,
                                                    "class": "Boundary Condition Error",
                                                    "cve": [
                                                        "CVE-2005-2978"
                                                    ],
                                                    "local": "no",
                                                    "remote": "yes",
                                                    "title": "NetPBM PNMToPNG Buffer Overflow Vulnerability"
                                                }


class IsFPMongoDbDriver(MongoDbDriver):
    def __init__(self):
        self.client = Mock(spec=pymongo.MongoClient)
        self.db = Mock()
        cursor_image_history = self.db.image_history.find.return_value
        cursor_image_history.sort.return_value = [
            {"_id": "5915ed36ff1f081833551af5", "timestamp": 1494609523.342605, "status": "Completed",
             "image_name": "alpine", "static_analysis": {"prog_lang_dependencies": {
             "dependencies_details": {"java": [], "python": [], "js": [], "ruby": [], "php": [], "nodejs": []},
             "vuln_dependencies": 0}, "os_packages": {"vuln_os_packages": 1, "os_packages_details": [
            {"version": "1.1.15", "vulnerabilities": [{"CVE-2016-8859": {"cvss_integrity_impact": "Partial",
             "cvss_access_vector": "Network", "cweid": "CWE-190", "cvss_access_complexity": "Low", "cvss_confidentiality_impact": "Partial",
             "mod_date": "07-03-2017", "cvss_exploit": 10, "cvss_vector": ["AV:N", "AC:L", "Au:N", "C:P", "I:P", "A:P"],
             "cvss_authentication": "None required",
             "summary": "Multiple integer overflows in the TRE library and musl libc allow attackers to cause memory corruption via a large number of (1) states or (2) tags, which triggers an out-of-bounds write.",
             "cveid": "CVE-2016-8859", "cvss_impact": 6.4, "pub_date": "13-02-2017", "cvss_base": 7.5,
             "cvss_availability_impact": "Partial"}}],
             "product": "musl", "is_vulnerable": True, "is_false_positive" : True},
            {"version": "1.25.1", "vulnerabilities": [], "product": "busybox", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "3.0.4", "vulnerabilities": [], "product": "alpine-baselayout", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "1.3", "vulnerabilities": [], "product": "alpine-keys", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "2.4.4", "vulnerabilities": [], "product": "libressl2.4-libcrypto", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "2.4.4", "vulnerabilities": [], "product": "libressl2.4-libssl", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "1.2.8", "vulnerabilities": [{"BID-95131": {"cve": ["CVE-2016-9840"], "bugtraq_id": 95131,
             "title": "zlib Multiple Denial of Service Vulnerabilities", "remote": "yes", "local": "no",
             "class": "Design Error"}}], "product": "zlib", "is_vulnerable": True, "is_false_positive" : False},
            {"version": "2.6.8", "vulnerabilities": [], "product": "apk-tools", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "1.1.6", "vulnerabilities": [], "product": "scanelf", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "1.1.15", "vulnerabilities": [], "product": "musl-utils", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "0.7", "vulnerabilities": [], "product": "libc-utils", "is_vulnerable": False, "is_false_positive" : False}],
                                                     "total_os_packages": 11, "ok_os_packages": 10}}}]


class UpdateFPMongoDbDriver(MongoDbDriver):
    def __init__(self):
        self.client = Mock(spec=pymongo.MongoClient)
        self.db = Mock()
        cursor_image_history = self.db.image_history.find.return_value
        cursor_image_history.sort.return_value = [
            {"_id": "5915ed36ff1f081833551af5", "timestamp": 1494609523.342605, "status": "Completed",
             "image_name": "alpine", "static_analysis": {"prog_lang_dependencies": {
             "dependencies_details": {"java": [], "python": [], "js": [], "ruby": [], "php": [], "nodejs": []},
             "vuln_dependencies": 0}, "os_packages": {"vuln_os_packages": 2, "os_packages_details": [
            {"version": "1.1.15", "vulnerabilities": [{"CVE-2016-8859": {"cvss_integrity_impact": "Partial",
             "cvss_access_vector": "Network", "cweid": "CWE-190", "cvss_access_complexity": "Low", "cvss_confidentiality_impact": "Partial",
             "mod_date": "07-03-2017", "cvss_exploit": 10, "cvss_vector": ["AV:N", "AC:L", "Au:N", "C:P", "I:P", "A:P"],
             "cvss_authentication": "None required",
             "summary": "Multiple integer overflows in the TRE library and musl libc allow attackers to cause memory corruption via a large number of (1) states or (2) tags, which triggers an out-of-bounds write.",
             "cveid": "CVE-2016-8859", "cvss_impact": 6.4, "pub_date": "13-02-2017", "cvss_base": 7.5,
             "cvss_availability_impact": "Partial"}}],
             "product": "musl", "is_vulnerable": True, "is_false_positive" : False},
            {"version": "1.25.1", "vulnerabilities": [], "product": "busybox", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "3.0.4", "vulnerabilities": [], "product": "alpine-baselayout", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "1.3", "vulnerabilities": [], "product": "alpine-keys", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "2.4.4", "vulnerabilities": [], "product": "libressl2.4-libcrypto", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "2.4.4", "vulnerabilities": [], "product": "libressl2.4-libssl", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "1.2.8", "vulnerabilities": [{"BID-95131": {"cve": ["CVE-2016-9840"], "bugtraq_id": 95131,
             "title": "zlib Multiple Denial of Service Vulnerabilities", "remote": "yes", "local": "no",
             "class": "Design Error"}}], "product": "zlib", "is_vulnerable": True, "is_false_positive" : False},
            {"version": "2.6.8", "vulnerabilities": [], "product": "apk-tools", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "1.1.6", "vulnerabilities": [], "product": "scanelf", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "1.1.15", "vulnerabilities": [], "product": "musl-utils", "is_vulnerable": False, "is_false_positive" : False},
            {"version": "0.7", "vulnerabilities": [], "product": "libc-utils", "is_vulnerable": False, "is_false_positive" : False}],
                                                     "total_os_packages": 11, "ok_os_packages": 9}}}]
        self.db.image_history.update.return_value = True


class BulkInfoMongoDbDriver(MongoDbDriver):
    def __init__(self):
        self.client = Mock(spec=pymongo.MongoClient)
        self.db = Mock()
        self.db.cve.create_index.return_value = True
        self.db.bid.create_index.return_value = True
        self.db.exploit_db.create_index.return_value = True
        self.db.falco_events.count.return_value = 0
        self.db.falco_events.create_index.return_value = True

if __name__ == '__main__':
    unittest.main()
