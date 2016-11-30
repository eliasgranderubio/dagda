import unittest
from unittest.mock import Mock
from dagda.vulnDB.mongodb_driver import MongoDbDriver
import pymongo


# -- Test suite

class MongoDbDriverTestCase(unittest.TestCase):

    def test_get_vulnerabilities_full_happy_path(self):
        mock_driver = TestingFullGetVulnMongoDbDriver()
        vulnerabilities = mock_driver.get_vulnerabilities('openldap')
        self.assertEqual(len(vulnerabilities), 6)
        self.assertEqual(vulnerabilities,
                         ['CVE-2002-2001', 'CVE-2002-2002', 'BID-1', 'BID-2', 'EXPLOIT_DB_ID-3', 'EXPLOIT_DB_ID-4'])


# -- Mock classes

class TestingFullGetVulnMongoDbDriver(MongoDbDriver):
    def __init__(self):
        self.client = Mock(spec=pymongo.MongoClient)
        self.db = Mock()
        cursor_cve = self.db.cve.find.return_value
        cursor_cve.sort.return_value = [{'cve_id': "CVE-2002-2001"}, {'cve_id': "CVE-2002-2002"}]
        cursor_bid = self.db.bid.find.return_value
        cursor_bid.sort.return_value = [{'bugtraq_id': 1}, {'bugtraq_id': 2}]
        cursor_expl = self.db.exploit_db.find.return_value
        cursor_expl.sort.return_value = [{'exploit_db_id': 3}, {'exploit_db_id': 4}]


if __name__ == '__main__':
    unittest.main()
