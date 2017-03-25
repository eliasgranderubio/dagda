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

import argparse
import re
from log.dagda_logger import DagdaLogger


class VulnCLIParser:

    # -- Public methods

    # VulnCLIParser Constructor
    def __init__(self):
        super(VulnCLIParser, self).__init__()
        self.parser = DagdaVulnParser(prog='dagda.py vuln', usage=vuln_parser_text)
        self.parser.add_argument('--init', action='store_true')
        self.parser.add_argument('--init_status', action='store_true')
        self.parser.add_argument('--bid', type=int)
        self.parser.add_argument('--cve', type=str)
        self.parser.add_argument('--cve_info', type=str)
        self.parser.add_argument('--exploit_db', type=int)
        self.parser.add_argument('--product', type=str)
        self.parser.add_argument('--product_version', type=str)
        self.args, self.unknown = self.parser.parse_known_args()
        # Verify command line arguments
        status = self.verify_args(self.args)
        if status != 0:
            exit(status)

    # -- Getters

    # Gets if initialization is required
    def is_initialization_required(self):
        return self.args.init

    # Gets if init status is requested
    def is_init_status_requested(self):
        return self.args.init_status

    # Gets CVE value
    def get_cve(self):
        return self.args.cve

    # Gets CVE value
    def get_cve_info(self):
        return self.args.cve_info

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
    def verify_args(args):
        if not args.init and not args.cve and not args.cve_info and not args.product and not args.product_version \
                and not args.bid and not args.exploit_db and not args.init_status:
            DagdaLogger.get_logger().error('Missing arguments.')
            return 1
        elif args.init and (args.cve or args.product or args.product_version or args.bid or args.exploit_db \
                            or args.init_status):
            DagdaLogger.get_logger().error('Argument --init: this argument must be alone.')
            return 2
        elif args.init_status and (args.cve or args.product or args.product_version or args.bid or args.cve \
                                   or args.cve_info or args.exploit_db or args.init):
            DagdaLogger.get_logger().error('Argument --init_status: this argument must be alone.')
            return 3
        elif args.cve:
            if args.init or args.init_status or args.product or args.product_version or args.bid or args.cve_info \
                    or args.exploit_db:
                DagdaLogger.get_logger().error('Argument --cve: this argument must be alone.')
                return 4
            else:
                regex = r"(CVE-[0-9]{4}-[0-9]{4})"
                search_obj = re.search(regex, args.cve)
                if not search_obj or len(search_obj.group(0)) != len(args.cve):
                    DagdaLogger.get_logger().error('Argument --cve: The cve format must look like to CVE-2002-1234.')
                    return 5
        elif args.cve_info:
            if args.init or args.init_status or args.product or args.product_version or args.bid or args.cve \
                    or args.exploit_db:
                DagdaLogger.get_logger().error('Argument --cve_info: this argument must be alone.')
                return 6
            else:
                regex = r"(CVE-[0-9]{4}-[0-9]{4})"
                search_obj = re.search(regex, args.cve_info)
                if not search_obj or len(search_obj.group(0)) != len(args.cve_info):
                    DagdaLogger.get_logger().error('Argument --cve_info: The cve format must look like to '
                                                   'CVE-2002-1234.')
                    return 7
        elif args.bid:
            if args.init or args.init_status or args.product or args.product_version or args.cve or args.cve_info \
                    or args.exploit_db:
                DagdaLogger.get_logger().error('Argument --bid: this argument must be alone.')
                return 8
            else:
                if args.bid <= 0:
                    DagdaLogger.get_logger().error('Argument --bid: The bid argument must be greater than zero.')
                    return 9
        elif args.exploit_db:
            if args.init or args.init_status or args.product or args.product_version or args.cve or args.cve_info \
                    or args.bid:
                DagdaLogger.get_logger().error('Argument --exploit_db: this argument must be alone.')
                return 10
            else:
                if args.exploit_db <= 0:
                    DagdaLogger.get_logger().error('Argument --exploit_db: The bid argument must be greater than zero.')
                    return 11
        elif args.product_version and not args.product:
            DagdaLogger.get_logger().error('Argument --product_version: this argument requires the --product argument.')
            return 12
        # Else
        return 0


# Custom parser

class DagdaVulnParser(argparse.ArgumentParser):

    # Overrides the error method
    def error(self, message):
        self.print_usage()
        exit(2)

    # Overrides the format help method
    def format_help(self):
        return vuln_parser_text


# Custom text

vuln_parser_text = '''usage: dagda.py vuln [-h] [--init] [--init_status]
                  [--bid BID] [--cve CVE] [--cve_info CVE] [--exploit_db EXPLOIT_DB]
                  [--product PRODUCT] [--product_version PRODUCT_VERSION]

Your personal CVE, BID & ExploitDB database.

Optional Arguments:
  -h, --help            show this help message and exit
  --init                initializes your local database with all CVEs provided
                        by NIST publications, all BugTraqs Ids (BIDs)
                        downloaded from the "http://www.securityfocus.com/"
                        pages (See my project "bidDB_downloader"
                        [https://github.com/eliasgranderubio/bidDB_downloader]
                        for details) and all exploits from Offensive Security
                        Exploit Database. If this argument is present, all
                        CVEs, BIDs and exploits of your local database will be
                        updated.
  --init_status         retrieves the initialization status
  --bid BID             all product with this BugTraq Id (BID) vulnerability
                        will be shown
  --cve CVE             all products with this CVE vulnerability will be shown
  --cve_info CVE        shows all details about this CVE vulnerability
  --exploit_db EXPLOIT_DB
                        all products with this Exploit_DB Id vulnerability
                        will be shown
  --product PRODUCT     all CVE/BID vulnerabilities and exploits of this
                        product will be shown
  --product_version PRODUCT_VERSION
                        extra filter for product query about its CVE/BID
                        vulnerabilities and exploits. If this argument is
                        present, the "--product" argument must be present too
'''
