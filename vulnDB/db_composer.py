import requests
import zlib
import progressbar
import json
import gzip
import io
import re
import time
import xml.etree.ElementTree as ET
from vulnDB.mongodb_driver import MongoDbDriver


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

        # Adding CVEs
        print("\nAdding CVEs ...", flush=True)
        time.sleep(1)  # Avoids race condition in stdout
        bar = progressbar.ProgressBar(redirect_stdout=True)
        for i in bar(range(2002, 2017)):
            self.mongoDbDriver.bulk_insert_cves(self.__get_cve_list_from_file(i))

        # Adding BugTraqs
        time.sleep(1)  # Avoids race condition in stdout
        print("\nAdding BugTraqs (BIDs) ...", flush=True)
        self.__get_and_insert_bug_traqs_from_file()
        time.sleep(1)  # Avoids race condition in stdout

    # -- Private methods

    # Gets and inserts BugTraq list from file
    def __get_and_insert_bug_traqs_from_file(self):
        r = requests.get(
            "https://github.com/eliasgranderubio/bidDB_downloader/raw/master/bonus_track/20161118_sf_db.json.gz")
        compressed_file = io.BytesIO(r.content)
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

    # -- Static methods

    # Generate CVE list from file
    @staticmethod
    def __get_cve_list_from_file(year):
        cve_set = set()
        r = requests.get("https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-" + str(year) + ".xml.gz")
        xml_file_content = zlib.decompress(r.content, 16 + zlib.MAX_WBITS)
        root = ET.fromstring(xml_file_content)
        for entry in root.findall("{http://scap.nist.gov/schema/feed/vulnerability/2.0}entry"):
            vuln_soft_list = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}vulnerable-software-list")
            if vuln_soft_list is not None:
                for vuln_product in vuln_soft_list.findall(
                        "{http://scap.nist.gov/schema/vulnerability/0.4}product"):
                    splitted_product = vuln_product.text.split(":")
                    if len(splitted_product) > 4:
                        item = entry.attrib.get("id") + "#" + splitted_product[3] + "#" + splitted_product[4]
                        if item not in cve_set:
                            cve_set.add(item)
        return list(cve_set)
