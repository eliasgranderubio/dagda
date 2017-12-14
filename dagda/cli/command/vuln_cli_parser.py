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
        self.parser.add_argument('--bid_info', type=int)
        self.parser.add_argument('--cve', type=str)
        self.parser.add_argument('--cve_info', type=str)
        self.parser.add_argument('--exploit_db', type=int)
        self.parser.add_argument('--exploit_db_info', type=int)
        self.parser.add_argument('--rhba', type=str)
        self.parser.add_argument('--rhba_info', type=str)
        self.parser.add_argument('--rhsa', type=str)
        self.parser.add_argument('--rhsa_info', type=str)
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

    # Gets RHSA value
    def get_rhsa(self):
        return self.args.rhsa

    # Gets RHSA value
    def get_rhsa_info(self):
        return self.args.rhsa_info

    # Gets RHBA value
    def get_rhba(self):
        return self.args.rhba

    # Gets RHBA value
    def get_rhba_info(self):
        return self.args.rhba_info

    # Gets BID value
    def get_bid(self):
        return self.args.bid

    # Gets BID value
    def get_bid_info(self):
        return self.args.bid_info

    # Gets Exploit_DB Id value
    def get_exploit_db_id(self):
        return self.args.exploit_db

    # Gets Exploit_DB Id value
    def get_exploit_db_info_id(self):
        return self.args.exploit_db_info

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
                and not args.bid and not args.bid_info and not args.exploit_db and not args.exploit_db_info \
                and not args.init_status and not args.rhba and not args.rhsa and not args.rhba_info \
                and not args.rhsa_info:
            DagdaLogger.get_logger().error('Missing arguments.')
            return 1
        elif args.init and (args.cve or args.product or args.product_version or args.bid or args.bid_info \
                            or args.exploit_db or args.exploit_db_info or args.init_status or args.rhba or args.rhsa \
                            or args.rhba_info or args.rhsa_info):
            DagdaLogger.get_logger().error('Argument --init: this argument must be alone.')
            return 2
        elif args.init_status and (args.cve or args.product or args.product_version or args.bid or args.cve \
                                   or args.cve_info or args.bid_info or args.exploit_db or args.exploit_db_info \
                                   or args.init or args.rhba or args.rhsa or args.rhba_info or args.rhsa_info):
            DagdaLogger.get_logger().error('Argument --init_status: this argument must be alone.')
            return 3
        elif args.cve:
            if args.init or args.init_status or args.product or args.product_version or args.bid or args.cve_info \
                    or args.exploit_db or args.bid_info or args.exploit_db_info or args.rhba or args.rhsa \
                    or args.rhba_info or args.rhsa_info:
                DagdaLogger.get_logger().error('Argument --cve: this argument must be alone.')
                return 4
            else:
                regex = r"(CVE-[0-9]{4}-[0-9]{4,5})"
                search_obj = re.search(regex, args.cve)
                if not search_obj or len(search_obj.group(0)) != len(args.cve):
                    DagdaLogger.get_logger().error('Argument --cve: The cve format must look like to CVE-2002-1234.')
                    return 5
        elif args.cve_info:
            if args.init or args.init_status or args.product or args.product_version or args.bid or args.cve \
                    or args.exploit_db or args.bid_info or args.exploit_db_info or args.rhba or args.rhsa \
                    or args.rhba_info or args.rhsa_info:
                DagdaLogger.get_logger().error('Argument --cve_info: this argument must be alone.')
                return 6
            else:
                regex = r"(CVE-[0-9]{4}-[0-9]{4,5})"
                search_obj = re.search(regex, args.cve_info)
                if not search_obj or len(search_obj.group(0)) != len(args.cve_info):
                    DagdaLogger.get_logger().error('Argument --cve_info: The cve format must look like to '
                                                   'CVE-2002-1234.')
                    return 7
        elif args.bid:
            if args.init or args.init_status or args.product or args.product_version or args.cve or args.cve_info \
                    or args.exploit_db or args.bid_info or args.exploit_db_info or args.rhba or args.rhsa \
                    or args.rhba_info or args.rhsa_info:
                DagdaLogger.get_logger().error('Argument --bid: this argument must be alone.')
                return 8
            else:
                if args.bid <= 0:
                    DagdaLogger.get_logger().error('Argument --bid: The bid argument must be greater than zero.')
                    return 9
        elif args.bid_info:
            if args.init or args.init_status or args.product or args.product_version or args.cve or args.cve_info \
                    or args.exploit_db or args.bid or args.exploit_db_info or args.rhba or args.rhsa \
                    or args.rhba_info or args.rhsa_info:
                DagdaLogger.get_logger().error('Argument --bid_info: this argument must be alone.')
                return 10
            else:
                if args.bid_info <= 0:
                    DagdaLogger.get_logger().error(
                        'Argument --bid_info: The bid argument must be greater than zero.')
                    return 11
        elif args.exploit_db:
            if args.init or args.init_status or args.product or args.product_version or args.cve or args.cve_info \
                    or args.bid or args.bid_info or args.exploit_db_info or args.rhba or args.rhsa \
                    or args.rhba_info or args.rhsa_info:
                DagdaLogger.get_logger().error('Argument --exploit_db: this argument must be alone.')
                return 12
            else:
                if args.exploit_db <= 0:
                    DagdaLogger.get_logger().error('Argument --exploit_db: The exploit_db argument must be '
                                                   'greater than zero.')
                    return 13
        elif args.exploit_db_info:
            if args.init or args.init_status or args.product or args.product_version or args.cve or args.cve_info \
                    or args.bid or args.bid_info or args.exploit_db or args.rhba or args.rhsa \
                    or args.rhba_info or args.rhsa_info:
                DagdaLogger.get_logger().error('Argument --exploit_db_info: this argument must be alone.')
                return 14
            else:
                if args.exploit_db_info <= 0:
                    DagdaLogger.get_logger().error('Argument --exploit_db_info: The exploit_db_info argument '
                                                   'must be greater than zero.')
                    return 15
        elif args.product_version and not args.product:
            DagdaLogger.get_logger().error('Argument --product_version: this argument requires the --product argument.')
            return 16
        elif args.rhba:
            if args.init or args.init_status or args.product or args.product_version or args.bid or args.cve_info \
                    or args.exploit_db or args.bid_info or args.exploit_db_info or args.cve or args.rhsa \
                    or args.rhba_info or args.rhsa_info:
                DagdaLogger.get_logger().error('Argument --rhba: this argument must be alone.')
                return 17
            else:
                regex = r"(RHBA-[0-9]{4}:[0-9]+)"
                search_obj = re.search(regex, args.rhba)
                if not search_obj or len(search_obj.group(0)) != len(args.rhba):
                    DagdaLogger.get_logger().error('Argument --rhba: The rhba format must look like to RHBA-2012:234.')
                    return 18
        elif args.rhba_info:
            if args.init or args.init_status or args.product or args.product_version or args.bid or args.cve_info \
                    or args.exploit_db or args.bid_info or args.exploit_db_info or args.cve or args.rhsa \
                    or args.rhba or args.rhsa_info:
                DagdaLogger.get_logger().error('Argument --rhba_info: this argument must be alone.')
                return 19
            else:
                regex = r"(RHBA-[0-9]{4}:[0-9]+)"
                search_obj = re.search(regex, args.rhba_info)
                if not search_obj or len(search_obj.group(0)) != len(args.rhba_info):
                    DagdaLogger.get_logger().error(
                        'Argument --rhba_info: The rhba format must look like to RHBA-2012:234.')
                    return 20
        elif args.rhsa:
            if args.init or args.init_status or args.product or args.product_version or args.bid or args.cve_info \
                    or args.exploit_db or args.bid_info or args.exploit_db_info or args.cve or args.rhba \
                    or args.rhba_info or args.rhsa_info:
                DagdaLogger.get_logger().error('Argument --rhsa: this argument must be alone.')
                return 21
            else:
                regex = r"(RHSA-[0-9]{4}:[0-9]+)"
                search_obj = re.search(regex, args.rhsa)
                if not search_obj or len(search_obj.group(0)) != len(args.rhsa):
                    DagdaLogger.get_logger().error(
                        'Argument --rhsa: The rhba format must look like to RHSA-2012:234.')
                    return 22
        elif args.rhsa_info:
            if args.init or args.init_status or args.product or args.product_version or args.bid or args.cve_info \
                    or args.exploit_db or args.bid_info or args.exploit_db_info or args.cve or args.rhsa \
                    or args.rhba or args.rhba_info:
                DagdaLogger.get_logger().error('Argument --rhsa_info: this argument must be alone.')
                return 23
            else:
                regex = r"(RHSA-[0-9]{4}:[0-9]+)"
                search_obj = re.search(regex, args.rhsa_info)
                if not search_obj or len(search_obj.group(0)) != len(args.rhsa_info):
                    DagdaLogger.get_logger().error(
                        'Argument --rhsa_info: The rhsa format must look like to RHSA-2012:234.')
                    return 24
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
                  [--bid BID] [--bid_info BID] [--cve CVE] [--cve_info CVE] 
                  [--exploit_db EXPLOIT_DB] [--exploit_db_info EXPLOIT_DB]
                  [--rhba RHBA] [--rhba_info RHBA] [--rhsa RHSA] [--rhsa_info RHSA] 
                  [--product PRODUCT] [--product_version PRODUCT_VERSION]

Your personal CVE, BID, RHBA, RHSA & ExploitDB database.

Optional Arguments:
  -h, --help            show this help message and exit
  --init                initializes your local database with all CVEs provided
                        by NIST publications, all BugTraqs Ids (BIDs)
                        downloaded from the "http://www.securityfocus.com/"
                        pages (See my "bidDB_downloader" project for details
                        [https://github.com/eliasgranderubio/bidDB_downloader]
                        for details), all RHSAs (Red Hat Security Advisories) 
                        and RHBAs (Red Hat Bug Advisories) provided by Red Hat 
                        publications, and all exploits from Offensive Security
                        Exploit Database. If this argument is present, all
                        CVEs, BIDs, RHBAs, RHSAs and exploits of your local 
                        database will be updated.
  --init_status         retrieves the initialization status
  
  --bid BID             all product with this BugTraq Id (BID) vulnerability
                        will be shown
  --bid_info BID        shows all details about this BugTraq Id (BID)
                        
  --cve CVE             all products with this CVE vulnerability will be shown
  --cve_info CVE        shows all details about this CVE vulnerability
  
  --exploit_db EXPLOIT_DB
                        all products with this Exploit_DB Id vulnerability
                        will be shown
  --exploit_db_info EXPLOIT_DB
                        shows all details about this exploit
                        
  --rhba RHBA           all products with this RHBA vulnerability will be shown
  --rhba_info RHBA      shows all details about this RHBA vulnerability                        

  --rhsa RHSA           all products with this RHSA vulnerability will be shown
  --rhsa_info RHSA      shows all details about this RHSA vulnerability 
                        
  --product PRODUCT     all CVE/BID/RHBA/RHSA vulnerabilities and exploits of this
                        product will be shown
  --product_version PRODUCT_VERSION
                        extra filter for product query about CVE/BID/RHBA/RHSA
                        vulnerabilities and exploits. If this argument is
                        present, the "--product" argument must be present too
'''
