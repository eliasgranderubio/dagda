import argparse
import re
import sys


class VulnDBCLIParser:

    # -- Public methods

    # CVEDBCLIParser Constructor
    def __init__(self):
        super(VulnDBCLIParser, self).__init__()
        self.parser = argparse.ArgumentParser(prog='vuln_db.py', description='Your personal CVE, BID & ExploitDB '
                                                                             'database.')
        self.parser.add_argument('--init', action='store_true',
                                 help='initializes your local database with all CVEs provided by NIST publications, '
                                      'all BugTraqs Ids (BIDs) downloaded from the "http://www.securityfocus.com/"'
                                      ' pages (See my project "bidDB_downloader" '
                                      '[https://github.com/eliasgranderubio/bidDB_downloader] for details) and all '
                                      'exploits from Offensive Security Exploit Database. '
                                      'If this argument is present, all CVEs, BIDs and exploits of your local '
                                      'database will be removed and then, will be inserted again with all updated '
                                      'CVEs, BIDs and exploits.')
        self.parser.add_argument('--bid', type=int,
                                 help='all product with this BugTraq Id (BID) vulnerability will be shown')
        self.parser.add_argument('--cve', help='all products with this CVE vulnerability will be shown')
        self.parser.add_argument('--exploit_db', type=int, help='all products with this Exploit_DB Id vulnerability '
                                                                'will be shown')
        self.parser.add_argument('--product', help='all CVE/BID vulnerabilities and exploits of this product will be '
                                                   'shown')
        self.parser.add_argument('--product_version',
                                 help='extra filter for product query about its CVE/BID vulnerabilities and exploits. If'
                                      ' this argument is present, the "--product" argument must be present too')
        self.parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.2.0',
                                 help='show the version message and exit')
        self.args = self.parser.parse_args()
        self.__verify_args()

    # -- Getters

    # Gets if initialization is required
    def is_initialization_required(self):
        return self.args.init

    # Gets CVE value
    def get_cve(self):
        return self.args.cve

    # Gets BID value
    def get_bid(self):
        return self.args.bid

    # Gets Exploit_DB Id value
    def get_exploit_db_id(self):
        return self.args.exploit_db

    # Gets the product
    def get_product(self):
        return self.args.product

    # Gets the product version
    def get_product_version(self):
        return self.args.product_version

    # -- Private methods

    # Verify command line arguments
    def __verify_args(self):
        if not self.args.init and not self.args.cve and not self.args.product and not self.args.product_version \
                and not self.args.bid and not self.args.exploit_db:
            print(self.parser.prog + ': error: missing arguments.', file=sys.stderr)
            exit(1)
        elif self.args.init and (self.args.cve or self.args.product or self.args.product_version \
                                 or self.args.bid or self.args.exploit_db):
            print(self.parser.prog + ': error: argument --init: this argument must be alone.', file=sys.stderr)
            exit(1)
        elif self.args.cve:
            if self.args.init or self.args.product or self.args.product_version or \
                    self.args.bid or self.args.exploit_db:
                print(self.parser.prog + ': error: argument --cve: this argument must be alone.', file=sys.stderr)
                exit(1)
            else:
                regex = r"(CVE-[0-9]{4}-[0-9]{4})"
                search_obj = re.search(regex, self.args.cve)
                if not search_obj or len(search_obj.group(0)) != len(self.args.cve):
                    print(self.parser.prog + ': error: argument --cve: The cve format must look like to CVE-2002-1234.',
                          file=sys.stderr)
                    exit(2)
        elif self.args.bid:
            if self.args.init or self.args.product or self.args.product_version or self.args.cve \
                    or self.args.exploit_db:
                print(self.parser.prog + ': error: argument --bid: this argument must be alone.', file=sys.stderr)
                exit(1)
            else:
                if self.args.bid <= 0:
                    print(self.parser.prog + ': error: argument --bid: The bid argument must be greater than zero.',
                          file=sys.stderr)
                    exit(2)
        elif self.args.exploit_db:
            if self.args.init or self.args.product or self.args.product_version or self.args.cve or self.args.bid:
                print(self.parser.prog + ': error: argument --exploit_db: this argument must be alone.',
                      file=sys.stderr)
                exit(1)
            else:
                if self.args.exploit_db <= 0:
                    print(self.parser.prog + ': error: argument --exploit_db: The bid argument must be greater than '
                                             'zero.',
                          file=sys.stderr)
                    exit(2)
        elif self.args.product_version and not self.args.product:
            print(self.parser.prog + ': error: argument --product_version: this argument requires the '
                                     '--product argument.', file=sys.stderr)
            exit(1)
