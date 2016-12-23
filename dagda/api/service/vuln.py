import json
import re
from flask import Blueprint
from driver.mongodb_driver import MongoDbDriver


# -- Global

vuln_api = Blueprint('vuln_api', __name__)
mongodb_driver = MongoDbDriver()


# Gets CVEs, BIDs and Exploit_DB Ids by product and version
@vuln_api.route('/v1/vuln/products/<string:product>', methods=['GET'])
@vuln_api.route('/v1/vuln/products/<string:product>/<string:version>', methods=['GET'])
def get_vulns_by_product_and_version(product, version=None):
    vulns = mongodb_driver.get_vulnerabilities(product, version)
    if len(vulns) == 0:
        return '', 404
    return json.dumps(vulns, sort_keys=True)


# Gets products by CVE
@vuln_api.route('/v1/vuln/cve/<string:cve_id>', methods=['GET'])
def get_products_by_cve(cve_id):
    regex = r"(CVE-[0-9]{4}-[0-9]{4})"
    search_obj = re.search(regex, cve_id)
    if not search_obj or len(search_obj.group(0)) != len(cve_id):
        return '', 400
    products = mongodb_driver.get_products_by_cve(cve_id)
    if len(products) == 0:
        return '', 404
    return json.dumps(products, sort_keys=True)


# Gets products by BID
@vuln_api.route('/v1/vuln/bid/<int:bid_id>', methods=['GET'])
def get_products_by_bid(bid_id):
    products = mongodb_driver.get_products_by_bid(bid_id)
    if len(products) == 0:
        return '', 404
    return json.dumps(products, sort_keys=True)


# Gets products by Exploit DB Id
@vuln_api.route('/v1/vuln/exploit/<int:exploit_id>', methods=['GET'])
def get_products_by_exploit_id(exploit_id):
    products = mongodb_driver.get_products_by_exploit_db_id(exploit_id)
    if len(products) == 0:
        return '', 404
    return json.dumps(products, sort_keys=True)
