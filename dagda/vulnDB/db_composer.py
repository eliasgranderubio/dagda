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
from api.internal.internal_server import InternalServer
from vulnDB.ext_source_util import get_bug_traqs_lists_from_file
from vulnDB.ext_source_util import get_bug_traqs_lists_from_online_mode
from vulnDB.ext_source_util import get_cve_list_from_file
from vulnDB.ext_source_util import get_exploit_db_list_from_csv
from vulnDB.ext_source_util import get_http_resource_content
from vulnDB.bid_downloader import bid_downloader
from vulnDB.ext_source_util import get_cve_description_from_file
from vulnDB.ext_source_util import get_cve_cweid_from_file


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
        # -- CVE
        # Adding or updating CVEs
        first_year = self.mongoDbDriver.remove_only_cve_for_update()
        for i in range(first_year, next_year):
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

        # -- Exploit DB
        # Adding or updating Exploit_db and Exploit_db info
        self.mongoDbDriver.delete_exploit_db_collection()
        self.mongoDbDriver.delete_exploit_db_info_collection()
        csv_content = get_http_resource_content(
            'https://github.com/offensive-security/exploit-database/raw/master/files.csv')
        exploit_db_list, exploit_db_info_list = get_exploit_db_list_from_csv(csv_content.decode("utf-8"))
        self.mongoDbDriver.bulk_insert_exploit_db_ids(exploit_db_list)
        self.mongoDbDriver.bulk_insert_exploit_db_info(exploit_db_info_list)

        # -- BID
        # Adding BugTraqs from 20170507_sf_db.json.gz, where 98325 is the max bid in the gz file
        max_bid = self.mongoDbDriver.get_max_bid_inserted()
        if max_bid < 98325:
            # Clean
            if max_bid != 0:
                self.mongoDbDriver.delete_bid_collection()
                self.mongoDbDriver.delete_bid_info_collection()
            # Adding BIDs
            compressed_file = io.BytesIO(get_http_resource_content(
                "https://github.com/eliasgranderubio/bidDB_downloader/raw/master/bonus_track/20170507_sf_db.json.gz"))
            bid_items_array, bid_detail_array = get_bug_traqs_lists_from_file(compressed_file)
            # Insert BIDs
            for bid_items_list in bid_items_array:
                self.mongoDbDriver.bulk_insert_bids(bid_items_list)
                bid_items_list.clear()
            # Insert BID details
            self.mongoDbDriver.bulk_insert_bid_info(bid_detail_array)
            bid_detail_array.clear()
            # Set the new max bid
            max_bid = 98325

        # Updating BugTraqs from http://www.securityfocus.com/
        bid_items_array, bid_detail_array = get_bug_traqs_lists_from_online_mode(bid_downloader(first_bid=max_bid+1,
                                                                                                last_bid=100500))
        # Insert BIDs
        for bid_items_list in bid_items_array:
            self.mongoDbDriver.bulk_insert_bids(bid_items_list)
            bid_items_list.clear()
        # Insert BID details
        self.mongoDbDriver.bulk_insert_bid_info(bid_detail_array)
        bid_detail_array.clear()
