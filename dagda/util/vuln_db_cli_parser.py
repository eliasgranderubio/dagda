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
        self.parser.add_argument('--exploit_db', type=int,
                                 help='all products with this Exploit_DB Id vulnerability will be shown')
        self.parser.add_argument('--product',
                                 help='all CVE/BID vulnerabilities and exploits of this product will be shown')
        self.parser.add_argument('--product_version',
                                 help='extra filter for product query about its CVE/BID vulnerabilities and exploits.'
                                      ' If this argument is present, the "--product" argument must be present too')
        self.parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.2.0',
                                 help='show the version message and exit')
        self.args = self.parser.parse_args()
        # Verify command line arguments
        status = self.verify_args(self.parser.prog, self.args)
        if status != 0:
            exit(status)

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

    # -- Static methods

    # Verify command line arguments
    @staticmethod
    def verify_args(prog, args):
        if not args.init and not args.cve and not args.product and not args.product_version and not args.bid \
                and not args.exploit_db:
            print(prog + ': error: missing arguments.', file=sys.stderr)
            return 1
        elif args.init and (args.cve or args.product or args.product_version or args.bid or args.exploit_db):
            print(prog + ': error: argument --init: this argument must be alone.', file=sys.stderr)
            return 2
        elif args.cve:
            if args.init or args.product or args.product_version or args.bid or args.exploit_db:
                print(prog + ': error: argument --cve: this argument must be alone.', file=sys.stderr)
                return 3
            else:
                regex = r"(CVE-[0-9]{4}-[0-9]{4})"
                search_obj = re.search(regex, args.cve)
                if not search_obj or len(search_obj.group(0)) != len(args.cve):
                    print(prog + ': error: argument --cve: The cve format must look like to CVE-2002-1234.',
                          file=sys.stderr)
                    return 4
        elif args.bid:
            if args.init or args.product or args.product_version or args.cve or args.exploit_db:
                print(prog + ': error: argument --bid: this argument must be alone.', file=sys.stderr)
                return 5
            else:
                if args.bid <= 0:
                    print(prog + ': error: argument --bid: The bid argument must be greater than zero.',
                          file=sys.stderr)
                    return 6
        elif args.exploit_db:
            if args.init or args.product or args.product_version or args.cve or args.bid:
                print(prog + ': error: argument --exploit_db: this argument must be alone.',
                      file=sys.stderr)
                return 7
            else:
                if args.exploit_db <= 0:
                    print(prog + ': error: argument --exploit_db: The bid argument must be greater than zero.',
                          file=sys.stderr)
                    return 8
        elif args.product_version and not args.product:
            print(prog + ': error: argument --product_version: this argument requires the --product argument.',
                  file=sys.stderr)
            return 9
        # Else
        return 0
