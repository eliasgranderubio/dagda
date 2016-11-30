import unittest
from unittest.mock import Mock
from dagda.vulnDB.mongodb_driver import MongoDbDriver
import pymongo


# -- Test suite

class MongoDbDriverTestCase(unittest.TestCase):

    def test_get_vulnerabilities_product_full_happy_path(self):
        mock_driver = FullGetVulnProdMongoDbDriver()
        vulnerabilities = mock_driver.get_vulnerabilities('openldap')
        self.assertEqual(len(vulnerabilities), 6)
        self.assertEqual(vulnerabilities,
                         ['CVE-2002-2001', 'CVE-2002-2002', 'BID-1', 'BID-2', 'EXPLOIT_DB_ID-3', 'EXPLOIT_DB_ID-4'])

    def test_get_vulnerabilities_product_and_version_full_happy_path(self):
        mock_driver = FullGetVulnProdAndVersionMongoDbDriver()
        vulnerabilities = mock_driver.get_vulnerabilities('openldap','2.2.20')
        self.assertEqual(len(vulnerabilities), 6)
        self.assertEqual(vulnerabilities,
                         ["CVE-2005-4442", "CVE-2006-2754", "CVE-2007-5707", "CVE-2011-4079", "BID-83610", "BID-83843"])


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


if __name__ == '__main__':
    unittest.main()
