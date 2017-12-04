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

import sys
import unittest

from cli.command.vuln_cli_parser import VulnCLIParser
from cli.command.vuln_cli_parser import DagdaVulnParser
from cli.command.vuln_cli_parser import vuln_parser_text


# -- Test suite

class VulnDBCliParserTestSuite(unittest.TestCase):

    def test_empty_args(self):
        empty_args = generate_args(False, False, None, None, None, None, None, None, None, None)
        status = VulnCLIParser.verify_args(empty_args)
        self.assertEqual(status, 1)

    def test_not_only_init(self):
        args = generate_args(True, False, None, None, 12345, None, None, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 2)

    def test_not_only_init_status(self):
        args = generate_args(False, True, None, None, 12345, None, None, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 3)

    def test_not_only_cve(self):
        args = generate_args(False, False, 'CVE-2002-1562', None, 12345, None, None, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 4)

    def test_bad_cve(self):
        args = generate_args(False, False, 'CVE-62', None, None, None, None, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 5)

    def test_not_only_cveinfo(self):
        args = generate_args(False, False, None,'CVE-2002-1562', None, 12345, None, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 6)

    def test_bad_cveinfo(self):
        args = generate_args(False, False, None, 'CVE-62', None, None, None, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 7)

    def test_not_only_bid(self):
        args = generate_args(False, False, None, None, 12345, None, 'openldap', None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 8)

    def test_bad_bid(self):
        args = generate_args(False, False, None, None, -12345, None, None, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 9)

    def test_not_only_bid_info(self):
        args = generate_args(False, False, None, None, None, 12345, 'openldap', None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 10)

    def test_bad_bid_info(self):
        args = generate_args(False, False, None, None, None, -12345, None, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 11)

    def test_not_only_exploit_db(self):
        args = generate_args(False, False, None, None, None, None, 12345, None, 'openldap', None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 12)

    def test_bad_exploit_db(self):
        args = generate_args(False, False, None, None, None, None, -12345, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 13)

    def test_not_only_exploit_db_info(self):
        args = generate_args(False, False, None, None, None, None, None, 12345, 'openldap', None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 14)

    def test_bad_exploit_db_info(self):
        args = generate_args(False, False, None, None, None, None, None, -12345, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 15)

    def test_only_product_version(self):
        args = generate_args(False, False, None, None, None, None, None, None, None, '2.30')
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 16)

    def test_ok(self):
        args = generate_args(False, False, None, None, None, None, None, None, 'openldap', '2.2.20')
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 0)

    def test_get_cve(self):
        sys.argv = ['dagda.py', 'vuln', '--cve', 'CVE-2002-2002']
        parsed_args = VulnCLIParser()
        self.assertEqual(parsed_args.get_cve(), 'CVE-2002-2002')

    def test_get_cve_info(self):
        sys.argv = ['dagda.py', 'vuln', '--cve_info', 'CVE-2002-2002']
        parsed_args = VulnCLIParser()
        self.assertEqual(parsed_args.get_cve_info(), 'CVE-2002-2002')

    def test_get_bid(self):
        sys.argv = ['dagda.py', 'vuln', '--bid', '15']
        parsed_args = VulnCLIParser()
        self.assertEqual(parsed_args.get_bid(), 15)

    def test_get_bid_info(self):
        sys.argv = ['dagda.py', 'vuln', '--bid_info', '15']
        parsed_args = VulnCLIParser()
        self.assertEqual(parsed_args.get_bid_info(), 15)

    def test_get_exploit_db_id(self):
        sys.argv = ['dagda.py', 'vuln', '--exploit_db', '15']
        parsed_args = VulnCLIParser()
        self.assertEqual(parsed_args.get_exploit_db_id(), 15)

    def test_get_exploit_db_info_id(self):
        sys.argv = ['dagda.py', 'vuln', '--exploit_db_info', '15']
        parsed_args = VulnCLIParser()
        self.assertEqual(parsed_args.get_exploit_db_info_id(), 15)

    def test_check_full_happy_path(self):
        sys.argv = ['dagda.py', 'vuln', '--product', 'openldap', '--product_version', '2.2.20']
        parsed_args = VulnCLIParser()
        self.assertEqual(parsed_args.get_product(), 'openldap')
        self.assertEqual(parsed_args.get_product_version(), '2.2.20')

    def test_check_exit_1(self):
        sys.argv = ['dagda.py', 'vuln']
        with self.assertRaises(SystemExit) as cm:
            VulnCLIParser()
        self.assertEqual(cm.exception.code, 1)

    def test_DagdaVulnParser_exit_2(self):
        with self.assertRaises(SystemExit) as cm:
            DagdaVulnParser().error("fail")
        self.assertEqual(cm.exception.code, 2)

    def test_DagdaVulnParser_format_help(self):
        self.assertEqual(DagdaVulnParser().format_help(), vuln_parser_text)


# -- Util methods

def generate_args(init, init_status, cve, cve_info, bid, bid_info, exploit_db, exploit_db_info, product,
                  product_version):
    return AttrDict([('init', init), ('init_status', init_status), ('cve', cve), ('cve_info', cve_info), ('bid', bid),
                     ('bid_info', bid_info), ('exploit_db', exploit_db), ('exploit_db_info', exploit_db_info),
                      ('product', product), ('product_version', product_version)])


# -- Util classes

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


if __name__ == '__main__':
    unittest.main()
