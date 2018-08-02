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

import io
from datetime import date
from log.dagda_logger import DagdaLogger
from api.internal.internal_server import InternalServer
from vulnDB.ext_source_util import get_bug_traqs_lists_from_file
from vulnDB.ext_source_util import get_bug_traqs_lists_from_online_mode
from vulnDB.ext_source_util import get_cve_list_from_file
from vulnDB.ext_source_util import get_exploit_db_list_from_csv
from vulnDB.ext_source_util import get_http_resource_content
from vulnDB.bid_downloader import bid_downloader
from vulnDB.ext_source_util import get_cve_description_from_file
from vulnDB.ext_source_util import get_cve_cweid_from_file
from vulnDB.ext_source_util import get_rhsa_and_rhba_lists_from_file


# Static field
next_year = date.today().year + 1


# DBComposer class
class DBComposer:

    # -- Public methods

    # DBComposer Constructor
    def __init__(self):
        super(DBComposer, self).__init__()
        self.mongoDbDriver = InternalServer.get_mongodb_driver()

    # Compose vuln DB
    def compose_vuln_db(self):
        if InternalServer.is_debug_logging_enabled():
            DagdaLogger.get_logger().debug('ENTRY to the method for composing VulnDB')

        # -- CVE
        # Adding or updating CVEs
        if InternalServer.is_debug_logging_enabled():
            DagdaLogger.get_logger().debug('Updating CVE collection ...')

        first_year = self.mongoDbDriver.remove_only_cve_for_update()
        for i in range(first_year, next_year):
            if InternalServer.is_debug_logging_enabled():
                DagdaLogger.get_logger().debug('... Including CVEs - ' + str(i))

            compressed_content = get_http_resource_content(
                "https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-" + str(i) + ".xml.gz")
            cve_list = get_cve_list_from_file(compressed_content, i)
            if len(cve_list) > 0:
                self.mongoDbDriver.bulk_insert_cves(cve_list)

            # Add CVE info collection with additional info like score
            compressed_content_info = get_http_resource_content("https://nvd.nist.gov/download/nvdcve-"
                                                                + str(i) + ".xml.zip")
            cve_info_list = get_cve_description_from_file(compressed_content_info)
            compressed_ext_content_info = \
                get_http_resource_content("https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-"
                                                                    + str(i) + ".xml.zip")
            cve_ext_info_list = get_cve_cweid_from_file(compressed_ext_content_info, cve_info_list)
            if len(cve_ext_info_list) > 0:
                self.mongoDbDriver.bulk_insert_cves_info(cve_ext_info_list)

        if InternalServer.is_debug_logging_enabled():
            DagdaLogger.get_logger().debug('CVE collection updated')

        # -- Exploit DB
        # Adding or updating Exploit_db and Exploit_db info
        if InternalServer.is_debug_logging_enabled():
            DagdaLogger.get_logger().debug('Updating Exploit DB collection ...')

        self.mongoDbDriver.delete_exploit_db_collection()
        self.mongoDbDriver.delete_exploit_db_info_collection()
        csv_content = get_http_resource_content(
            'https://raw.githubusercontent.com/offensive-security/exploit-database/master/files_exploits.csv')
        exploit_db_list, exploit_db_info_list = get_exploit_db_list_from_csv(csv_content.decode("utf-8"))
        self.mongoDbDriver.bulk_insert_exploit_db_ids(exploit_db_list)
        self.mongoDbDriver.bulk_insert_exploit_db_info(exploit_db_info_list)

        if InternalServer.is_debug_logging_enabled():
            DagdaLogger.get_logger().debug('Exploit DB collection updated')

        # -- BID
        # Adding BugTraqs from 20180328_sf_db.json.gz, where 103525 is the max bid in the gz file
        if InternalServer.is_debug_logging_enabled():
            DagdaLogger.get_logger().debug('Updating BugTraqs Id collection ...')

        max_bid = self.mongoDbDriver.get_max_bid_inserted()
        if max_bid < 103525:
            # Clean
            if max_bid != 0:
                self.mongoDbDriver.delete_bid_collection()
                self.mongoDbDriver.delete_bid_info_collection()
            # Adding BIDs
            compressed_file = io.BytesIO(get_http_resource_content(
                "https://github.com/eliasgranderubio/bidDB_downloader/raw/master/bonus_track/20180328_sf_db.json.gz"))
            bid_items_array, bid_detail_array = get_bug_traqs_lists_from_file(compressed_file)
            # Insert BIDs
            for bid_items_list in bid_items_array:
                self.mongoDbDriver.bulk_insert_bids(bid_items_list)
                bid_items_list.clear()
            # Insert BID details
            self.mongoDbDriver.bulk_insert_bid_info(bid_detail_array)
            bid_detail_array.clear()
            # Set the new max bid
            max_bid = 103525

        # Updating BugTraqs from http://www.securityfocus.com/
        bid_items_array, bid_detail_array = get_bug_traqs_lists_from_online_mode(bid_downloader(first_bid=max_bid+1,
                                                                                                last_bid=104000))
        # Insert BIDs
        if len(bid_items_array) > 0:
            for bid_items_list in bid_items_array:
                self.mongoDbDriver.bulk_insert_bids(bid_items_list)
                bid_items_list.clear()
        # Insert BID details
        if len(bid_detail_array) > 0:
            self.mongoDbDriver.bulk_insert_bid_info(bid_detail_array)
            bid_detail_array.clear()

        if InternalServer.is_debug_logging_enabled():
            DagdaLogger.get_logger().debug('BugTraqs Id collection updated')

        # -- RHSA (Red Hat Security Advisory) and RHBA (Red Hat Bug Advisory)
        # Adding or updating rhsa and rhba collections
        if InternalServer.is_debug_logging_enabled():
            DagdaLogger.get_logger().debug('Updating RHSA & RHBA collections ...')

        self.mongoDbDriver.delete_rhba_collection()
        self.mongoDbDriver.delete_rhba_info_collection()
        self.mongoDbDriver.delete_rhsa_collection()
        self.mongoDbDriver.delete_rhsa_info_collection()
        bz2_file = get_http_resource_content('https://www.redhat.com/security/data/oval/rhsa.tar.bz2')
        rhsa_list, rhba_list, rhsa_info_list, rhba_info_list = get_rhsa_and_rhba_lists_from_file(bz2_file)
        self.mongoDbDriver.bulk_insert_rhsa(rhsa_list)
        self.mongoDbDriver.bulk_insert_rhba(rhba_list)
        self.mongoDbDriver.bulk_insert_rhsa_info(rhsa_info_list)
        self.mongoDbDriver.bulk_insert_rhba_info(rhba_info_list)

        if InternalServer.is_debug_logging_enabled():
            DagdaLogger.get_logger().debug('RHSA & RHBA collections updated')

        if InternalServer.is_debug_logging_enabled():
            DagdaLogger.get_logger().debug('EXIT from the method for composing VulnDB')