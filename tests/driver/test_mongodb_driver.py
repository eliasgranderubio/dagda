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

if __name__ == '__main__':
    unittest.main()
