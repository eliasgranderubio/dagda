import io
import time

import progressbar

from driver.mongodb_driver import MongoDbDriver
from vulnDB.ext_source_util import get_bug_traqs_lists_from_file
from vulnDB.ext_source_util import get_cve_list_from_file
from vulnDB.ext_source_util import get_exploit_db_list_from_csv
from vulnDB.ext_source_util import get_http_resource_content


class DBComposer:

    # -- Public methods

    # DBComposer Constructor
    def __init__(self):
        super(DBComposer, self).__init__()
        self.mongoDbDriver = MongoDbDriver()

    # Compose vuln DB
    def compose_vuln_db(self):
        # Clean collections
        print("Cleaning vuln_DB ...", flush=True)
        self.mongoDbDriver.delete_cve_collection()
        self.mongoDbDriver.delete_bid_collection()
        self.mongoDbDriver.delete_exploit_db_collection()

        # Adding CVEs
        print("\nAdding CVEs ...", flush=True)
        time.sleep(1)  # Avoids race condition in stdout
        bar = progressbar.ProgressBar(redirect_stdout=True)
        for i in bar(range(2002, 2017)):
            compressed_content = get_http_resource_content(
                "https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-" + str(i) + ".xml.gz")
            self.mongoDbDriver.bulk_insert_cves(get_cve_list_from_file(compressed_content))

        # Adding Exploit_db
        time.sleep(1)  # Avoids race condition in stdout
        print("\nAdding Exploit_db ...", flush=True)
        csv_content = get_http_resource_content(
            'https://github.com/offensive-security/exploit-database/raw/master/files.csv')
        self.mongoDbDriver.bulk_insert_exploit_db_ids(get_exploit_db_list_from_csv(csv_content.decode("utf-8")))

        # Adding BugTraqs
        time.sleep(1)  # Avoids race condition in stdout
        print("\nAdding BugTraqs (BIDs) ...", flush=True)
        compressed_file = io.BytesIO(get_http_resource_content(
            "https://github.com/eliasgranderubio/bidDB_downloader/raw/master/bonus_track/20161118_sf_db.json.gz"))
        bid_items_array = get_bug_traqs_lists_from_file(compressed_file)
        bar = progressbar.ProgressBar(redirect_stdout=True)
        for bid_items_list in bar(bid_items_array):
            self.mongoDbDriver.bulk_insert_bids(bid_items_list)
            bid_items_list.clear()
