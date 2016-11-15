import requests
import xml.etree.ElementTree as ET
import zlib
from cveDB.mongodb_driver import MongoDbDriver
import progressbar


class DBComposer:

    # -- Public methods

    # DBComposer Constructor
    def __init__(self):
        super(DBComposer, self).__init__()
        self.mongoDbDriver = MongoDbDriver()

    # Compose CVE DB
    def compose_cve_db(self):
        self.mongoDbDriver.delete_cve_collection()
        bar = progressbar.ProgressBar()
        for i in bar(range(2002, 2017)):
            self.mongoDbDriver.bulk_insert(self.__get_cve_list_from_file(i))

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
