import sys
import unittest

from cli.command.vuln_cli_parser import VulnCLIParser


# -- Test suite

class VulnDBCliParserTestSuite(unittest.TestCase):

    def test_empty_args(self):
        empty_args = generate_args(False, False, None, None, None, None, None)
        status = VulnCLIParser.verify_args(empty_args)
        self.assertEqual(status, 1)

    def test_not_only_init(self):
        args = generate_args(True, False, None, 12345, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 2)

    def test_not_only_init_status(self):
        args = generate_args(False, True, None, 12345, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 3)

    def test_not_only_cve(self):
        args = generate_args(False, False, 'CVE-2002-1562', 12345, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 4)

    def test_bad_cve(self):
        args = generate_args(False, False, 'CVE-62', None, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 5)

    def test_not_only_bid(self):
        args = generate_args(False, False, None, 12345, 12345, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 6)

    def test_bad_bid(self):
        args = generate_args(False, False, None, -12345, None, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 7)

    def test_not_only_exploit_db(self):
        args = generate_args(False, False, None, None, 12345, 'openldap', None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 8)

    def test_bad_exploit_db(self):
        args = generate_args(False, False, None, None, -12345, None, None)
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 9)

    def test_only_product_version(self):
        args = generate_args(False, False, None, None, None, None, '2.30')
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 10)

    def test_ok(self):
        args = generate_args(False, False, None, None, None, 'openldap', '2.2.20')
        status = VulnCLIParser.verify_args(args)
        self.assertEqual(status, 0)

    def test_check_full_happy_path(self):
        sys.argv = ['dagda.py', 'vuln', '--product', 'openldap', '--product_version', '2.2.20']
        parsed_args = VulnCLIParser()
        self.assertEqual(parsed_args.get_product(), 'openldap')
        self.assertEqual(parsed_args.get_product_version(), '2.2.20')


# -- Util methods

def generate_args(init, init_status, cve, bid, exploit_db, product, product_version):
    return AttrDict([('init', init), ('init_status', init_status), ('cve', cve), ('bid', bid),
                     ('exploit_db', exploit_db), ('product', product), ('product_version', product_version)])


# -- Util classes

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


if __name__ == '__main__':
    unittest.main()
