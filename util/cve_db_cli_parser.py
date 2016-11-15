import argparse
import re
import sys


class CVEDBCLIParser:

    # -- Public methods

    # CVEDBCLIParser Constructor
    def __init__(self):
        super(CVEDBCLIParser, self).__init__()
        self.parser = argparse.ArgumentParser(prog='cve_db.py', description='Your personal CVE database.')
        self.parser.add_argument('--init', action='store_true',
                                 help='initialize your local database with all CVEs provided by NIST publications. '
                                      'If this argument is present, first all CVEs of your local database will be '
                                      'removed and inserted again with all CVEs provided by NIST publications')
        self.parser.add_argument('--cve', help='all products with this CVE vulnerability will be shown')
        self.parser.add_argument('--product', help='all CVE vulnerabilities of this product will be shown')
        self.parser.add_argument('--product_version', help='extra filter for product query about its CVE '
                                                           'vulnerabilities. If this argument is present, '
                                                           'the "--product" argument must be present too')
        self.parser.add_argument('--only_check', action='store_true', help='only checks if "--product" with '
                                                                              '"--product_version" has CVE '
                                                                              'vulnerabilities but they will not be '
                                                                              'shown')
        self.parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1.0',
                                 help='show the version message and exit')
        self.args = self.parser.parse_args()

    # -- Getters

    # Gets if initialization is required
    def is_initialization_required(self):
        if self.args.init:
            return True
        else:
            return False

    # Gets if product check is requested
    def is_only_product_check(self):
        if self.args.only_check:
            return True
        else:
            return False

    # Gets CVE value
    def get_cve(self):
        if not self.args.cve:
            return None
        else:
            regex = r"(CVE-[0-9]{4}-[0-9]{4})"
            search_obj = re.search(regex, self.args.cve)
            if search_obj and len(search_obj.group(0)) == len(self.args.cve):
                return search_obj.group(0)
            else:
                print(self.parser.prog + ': error: argument --cve: The cve format must look like to CVE-2002-1234.',
                      file=sys.stderr)
                exit(2)

    # Gets the product
    def get_product(self):
        return self.args.product

    # Gets the product version
    def get_product_version(self):
        return self.args.product_version
