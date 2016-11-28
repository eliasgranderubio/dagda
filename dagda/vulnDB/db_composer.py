import progressbar
import json
import gzip
import io
import re
import time
from vulnDB.mongodb_driver import MongoDbDriver
from vulnDB.ext_source_util import get_http_resource_content
from vulnDB.ext_source_util import get_cve_list_from_file
from vulnDB.ext_source_util import get_exploit_db_list_from_csv


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
        self.__get_and_insert_bug_traqs_from_file()

    # -- Private methods

    # Gets and inserts BugTraq list from file
    def __get_and_insert_bug_traqs_from_file(self):
        compressed_file = io.BytesIO(get_http_resource_content(
            "https://github.com/eliasgranderubio/bidDB_downloader/raw/master/bonus_track/20161118_sf_db.json.gz"))
        decompressed_file = gzip.GzipFile(fileobj=compressed_file)
        bar = progressbar.ProgressBar(redirect_stdout=True, max_value=len(decompressed_file.readlines()))
        decompressed_file.seek(0)
        counter = 0
        items = set()
        for line in decompressed_file:
            counter += 1
            bar.update(counter)
            try:
                json_data = json.loads(line.decode("utf-8"))
                bugtraq_id = json_data['bugtraq_id']
                vuln_products = json_data['vuln_products']
                for vuln_product in vuln_products:
                    matchObj = re.search("[\s\-]([0-9]+(\.[0-9]+)*)", vuln_product)
                    if matchObj:
                        version = matchObj.group()
                        version = version.rstrip().lstrip()
                        if version.startswith('-'):
                            version = version[1:]
                        if version:
                            product = vuln_product[:vuln_product.index(version) - 1].rstrip().lstrip()
                            item = str(bugtraq_id) + "#" + product.lower() + "#" + str(version)
                            if item not in items:
                                items.add(item)
            except:
                None
            # Bulk insert
            if len(items) > 8000:
                self.mongoDbDriver.bulk_insert_bids(list(items))
                items.clear()
        # Final bulk insert
        if len(items) > 0:
            self.mongoDbDriver.bulk_insert_bids(list(items))
            items.clear()
