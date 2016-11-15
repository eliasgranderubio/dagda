import pymongo
from util.config_parser import ConfigParser
import datetime


class MongoDbDriver:

    # -- Public methods

    # MongoDbDriver Constructor
    def __init__(self):
        super(MongoDbDriver, self).__init__()
        self.__config = ConfigParser()
        self.client = pymongo.MongoClient('mongodb://' + self.__config.get_mongodb_host() + ':' +
                                          self.__config.get_mongodb_port() + '/')
        self.db = self.client.cve_database

    # Bulk insert the cve list with the next format: <CVE-ID>#<product>#<version>
    def bulk_insert(self, cve_list):
        products = []
        for product in cve_list:
            splitted_product = product.split("#")
            data = {}
            data['cve_id'] = splitted_product[0]
            data['product'] = splitted_product[1]
            data['version'] = splitted_product[2]
            products.append(data)
        # Bulk insert
        self.db.cve.create_index([('product', pymongo.DESCENDING)])
        self.db.cve.insert_many(products)

    # Remove cve collection
    def delete_cve_collection(self):
        self.db.cve.remove()

    # Checks if the product has CVEs
    def has_cves(self, product, version=None):
        if not version:
            return self.db.cve.count({'product': product}) > 0
        else:
            return self.db.cve.count({'product': product, 'version': version}) > 0

    # Gets the product CVEs
    def get_cves(self, product, version=None):
        if not version:
            cursor = self.db.cve.find({'product': product}, {'product': 0, 'version': 0, '_id': 0})
        else:
            cursor = self.db.cve.find({'product': product, 'version': version}, {'product': 0, 'version': 0, '_id': 0})
        # Prepare output
        output = []
        for cve in cursor:
            if cve is not None:
                output.append(cve['cve_id'])
        # Return
        return output

    # Gets products from CVE
    def get_products(self, cve):
        cursor = self.db.cve.find({'cve_id': cve}, {'cve_id': 0, '_id': 0})
        # Prepare output
        output = []
        for product in cursor:
            if product is not None:
                output.append(product)
        # Return
        return output

    # Insert the docker image scan result to history
    def insert_docker_image_scan_result_to_history(self, scan_result):
        if self.db.image_history.count() == 0:
            self.db.image_history.create_index([('image_name', pymongo.DESCENDING)])
        self.db.image_history.insert(scan_result)

    # Gets docker image history
    def get_docker_image_history(self, image_name):
        cursor = self.db.image_history.find({'image_name': image_name}, {'_id': 0}).sort("timestamp",
                                                                                         pymongo.DESCENDING)
        # Prepare output
        output = []
        for scan in cursor:
            if scan is not None:
                scan['timestamp'] = str(datetime.datetime.utcfromtimestamp(scan['timestamp']))
                output.append(scan)
        # Return
        return output
