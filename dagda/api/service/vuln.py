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

import json
import re
import datetime
from flask import Blueprint
from api.internal.internal_server import InternalServer


# -- Global

vuln_api = Blueprint('vuln_api', __name__)


# Init or update the database
@vuln_api.route('/v1/vuln/init', methods=['POST'])
def init_or_update_db():
    InternalServer.get_dagda_edn().put({'msg': 'init_db'})
    # -- Return
    output = {}
    output['msg'] = 'Accepted the init db request'
    return json.dumps(output, sort_keys=True), 202


# Get the init db process status
@vuln_api.route('/v1/vuln/init-status', methods=['GET'])
def get_init_or_update_db_status():
    status = InternalServer.get_mongodb_driver().get_init_db_process_status()
    if not status['timestamp']:
        status['timestamp'] = '-'
    else:
        status['timestamp'] = str(datetime.datetime.utcfromtimestamp(status['timestamp']))
    return json.dumps(status, sort_keys=True)


# Gets CVEs, BIDs and Exploit_DB Ids by product and version
@vuln_api.route('/v1/vuln/products/<string:product>', methods=['GET'])
@vuln_api.route('/v1/vuln/products/<string:product>/<string:version>', methods=['GET'])
def get_vulns_by_product_and_version(product, version=None):
    vulns = InternalServer.get_mongodb_driver().get_vulnerabilities(product, version)
    if len(vulns) == 0:
        return json.dumps({'err': 404, 'msg': 'Vulnerabilities not found'}, sort_keys=True), 404
    return json.dumps(vulns, sort_keys=True)


# Gets products by CVE
@vuln_api.route('/v1/vuln/cve/<string:cve_id>', methods=['GET'])
def get_products_by_cve(cve_id):
    return _execute_cve_query(cve_id=cve_id, details=False)


# Gets CVE details
@vuln_api.route('/v1/vuln/cve/<string:cve_id>/details', methods=['GET'])
def get_cve_info_by_cve_id(cve_id):
    return _execute_cve_query(cve_id=cve_id, details=True)


# Gets products by BID
@vuln_api.route('/v1/vuln/bid/<int:bid_id>', methods=['GET'])
def get_products_by_bid(bid_id):
    products = InternalServer.get_mongodb_driver().get_products_by_bid(bid_id)
    if len(products) == 0:
        return json.dumps({'err': 404, 'msg': 'BugTraq Id not found'}, sort_keys=True), 404
    return json.dumps(products, sort_keys=True)


# Gets products by Exploit DB Id
@vuln_api.route('/v1/vuln/exploit/<int:exploit_id>', methods=['GET'])
def get_products_by_exploit_id(exploit_id):
    return _execute_exploit_query(exploit_id=exploit_id, details=False)


# Gets Exploit DB details
@vuln_api.route('/v1/vuln/exploit/<int:exploit_id>/details', methods=['GET'])
def get_exploit_details(exploit_id):
    return _execute_exploit_query(exploit_id=exploit_id, details=True)


# -- Private methods

# Executes CVE query
def _execute_cve_query(cve_id, details):
    regex = r"(CVE-[0-9]{4}-[0-9]{4,5})"
    search_obj = re.search(regex, cve_id)
    if not search_obj or len(search_obj.group(0)) != len(cve_id):
        return json.dumps({'err': 400, 'msg': 'Bad cve format'}, sort_keys=True), 400
    if not details:
        result = InternalServer.get_mongodb_driver().get_products_by_cve(cve_id)
    else:
        result = InternalServer.get_mongodb_driver().get_cve_info_by_cve_id(cve_id)
    if len(result) == 0:
        return json.dumps({'err': 404, 'msg': 'CVE not found'}, sort_keys=True), 404
    return json.dumps(result, sort_keys=True)


# Executes Exploit DB query
def _execute_exploit_query(exploit_id, details):
    if not details:
        result = InternalServer.get_mongodb_driver().get_products_by_exploit_db_id(exploit_id)
    else:
        result = InternalServer.get_mongodb_driver().get_exploit_info_by_id(exploit_id)
    if len(result) == 0:
        return json.dumps({'err': 404, 'msg': 'Exploit Id not found'}, sort_keys=True), 404
    return json.dumps(result, sort_keys=True)
