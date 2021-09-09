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
from vulnDB.db_composer import DBComposer
from log.dagda_logger import DagdaLogger

vuln_api = Blueprint("vuln_api", __name__)


# Init or update the database
@vuln_api.route("/v1/vuln/init", methods=["POST"])
def init_or_update_db():
    edn = InternalServer.get_dagda_edn()

    edn.put({"msg": "init_db"})
    queue_size = edn.qsize()
    DagdaLogger.get_logger().debug(f"EDN queue size after put: {queue_size}")
    # -- Return
    output = {}
    output["msg"] = "Accepted the init db request"
    return json.dumps(output, sort_keys=True), 202


# Get the init db process status
@vuln_api.route("/v1/vuln/init-status", methods=["GET"])
def get_init_or_update_db_status():
    status = InternalServer.get_mongodb_driver().get_init_db_process_status()
    if not status["timestamp"]:
        status["timestamp"] = "-"
    else:
        status["timestamp"] = str(
            datetime.datetime.utcfromtimestamp(status["timestamp"])
        )
    return json.dumps(status, sort_keys=True)


# Gets CVEs, BIDs and Exploit_DB Ids by product and version
@vuln_api.route("/v1/vuln/products/<string:product>", methods=["GET"])
@vuln_api.route("/v1/vuln/products/<string:product>/<string:version>", methods=["GET"])
def get_vulns_by_product_and_version(product, version=None):
    vulns = InternalServer.get_mongodb_driver().get_vulnerabilities(product, version)
    if len(vulns) == 0:
        return (
            json.dumps(
                {"err": 404, "msg": "Vulnerabilities not found"}, sort_keys=True
            ),
            404,
        )
    return json.dumps(vulns, sort_keys=True)


# Gets products by CVE
@vuln_api.route("/v1/vuln/cve/<string:cve_id>", methods=["GET"])
def get_products_by_cve(cve_id):
    return _execute_cve_query(cve_id=cve_id, details=False)


# Gets CVE details
@vuln_api.route("/v1/vuln/cve/<string:cve_id>/details", methods=["GET"])
def get_cve_info_by_cve_id(cve_id):
    return _execute_cve_query(cve_id=cve_id, details=True)


# Gets products by BID
@vuln_api.route("/v1/vuln/bid/<int:bid_id>", methods=["GET"])
def get_products_by_bid(bid_id):
    return _execute_bid_query(bid_id=bid_id, details=False)


# Gets BID details
@vuln_api.route("/v1/vuln/bid/<int:bid_id>/details", methods=["GET"])
def get_bid_details(bid_id):
    return _execute_bid_query(bid_id=bid_id, details=True)


# Gets products by Exploit DB Id
@vuln_api.route("/v1/vuln/exploit/<int:exploit_id>", methods=["GET"])
def get_products_by_exploit_id(exploit_id):
    return _execute_exploit_query(exploit_id=exploit_id, details=False)


# Gets Exploit DB details
@vuln_api.route("/v1/vuln/exploit/<int:exploit_id>/details", methods=["GET"])
def get_exploit_details(exploit_id):
    return _execute_exploit_query(exploit_id=exploit_id, details=True)


# Gets products by RHSA
@vuln_api.route("/v1/vuln/rhsa/<string:rhsa_id>", methods=["GET"])
def get_products_by_rhsa(rhsa_id):
    return _execute_rhsa_query(rhsa_id=rhsa_id, details=False)


# Gets RHSA details
@vuln_api.route("/v1/vuln/rhsa/<string:rhsa_id>/details", methods=["GET"])
def get_rhsa_details(rhsa_id):
    return _execute_rhsa_query(rhsa_id=rhsa_id, details=True)


# Gets products by RHBA
@vuln_api.route("/v1/vuln/rhba/<string:rhba_id>", methods=["GET"])
def get_products_by_rhba(rhba_id):
    return _execute_rhba_query(rhba_id=rhba_id, details=False)


# Gets RHBA details
@vuln_api.route("/v1/vuln/rhba/<string:rhba_id>/details", methods=["GET"])
def get_rhba_details(rhba_id):
    return _execute_rhba_query(rhba_id=rhba_id, details=True)


# Deletes mongo collections
@vuln_api.route("/v1/vuln/delete", methods=["DELETE"])
def delete_all():
    try:
        db_composer = DBComposer()
        db_composer.delete_all()
        return json.dumps({"status": "Deleting"}), 202
    except Exception as ex:
        message = "Unexpected exception of type {0} occurred while dropping the database: {1!r}".format(
            type(ex).__name__,
            ex.get_message() if type(ex).__name__ == "DagdaError" else ex.args,
        )
        DagdaLogger.get_logger().error(message)
        return json.dumps({"err": 500, "msg": message}, sort_keys=True), 500


# Deletes mongo document
@vuln_api.route("/v1/vuln/delete/<string:id>", methods=["DELETE"])
def delete_one(id: str):
    try:
        result = InternalServer.get_mongodb_driver().delete_one_image_history(id)
        if result.deleted_count == 1:
            return json.dumps({"status": 200, "data": result.raw_result}), 200
        else:
            return json.dumps(
                {
                    "status": 400,
                    "message": "Count of deleted documents was not 1.",
                    "data": result.raw_result,
                }
            )
    except Exception as ex:
        message = "Unexpected exception of type {0} occurred while deleting the document: {1!r}".format(
            type(ex).__name__,
            ex.get_message() if type(ex).__name__ == "DagdaError" else ex.args,
        )
        DagdaLogger.get_logger().error(message)
        return json.dumps({"err": 500, "msg": message}, sort_keys=True), 500


# -- Private methods

# Executes CVE query
def _execute_cve_query(cve_id, details):
    regex = r"(CVE-[0-9]{4}-[0-9]{4,5})"
    search_obj = re.search(regex, cve_id)
    if not search_obj or len(search_obj.group(0)) != len(cve_id):
        return json.dumps({"err": 400, "msg": "Bad cve format"}, sort_keys=True), 400
    if not details:
        result = InternalServer.get_mongodb_driver().get_products_by_cve(cve_id)
    else:
        result = InternalServer.get_mongodb_driver().get_cve_info_by_cve_id(cve_id)
    if len(result) == 0:
        return json.dumps({"err": 404, "msg": "CVE not found"}, sort_keys=True), 404
    return json.dumps(result, sort_keys=True)


# Executes BID query
def _execute_bid_query(bid_id, details):
    if not details:
        result = InternalServer.get_mongodb_driver().get_products_by_bid(bid_id)
    else:
        result = InternalServer.get_mongodb_driver().get_bid_info_by_id(bid_id)
    if len(result) == 0:
        return (
            json.dumps({"err": 404, "msg": "BugTraq Id not found"}, sort_keys=True),
            404,
        )
    return json.dumps(result, sort_keys=True)


# Executes Exploit DB query
def _execute_exploit_query(exploit_id, details):
    if not details:
        result = InternalServer.get_mongodb_driver().get_products_by_exploit_db_id(
            exploit_id
        )
    else:
        result = InternalServer.get_mongodb_driver().get_exploit_info_by_id(exploit_id)
    if len(result) == 0:
        return (
            json.dumps({"err": 404, "msg": "Exploit Id not found"}, sort_keys=True),
            404,
        )
    return json.dumps(result, sort_keys=True)


# Executes RHSA query
def _execute_rhsa_query(rhsa_id, details):
    regex = r"(RHSA-[0-9]{4}:[0-9]+)"
    search_obj = re.search(regex, rhsa_id)
    if not search_obj or len(search_obj.group(0)) != len(rhsa_id):
        return json.dumps({"err": 400, "msg": "Bad rhsa format"}, sort_keys=True), 400
    if not details:
        result = InternalServer.get_mongodb_driver().get_products_by_rhsa(rhsa_id)
    else:
        result = InternalServer.get_mongodb_driver().get_rhsa_info_by_id(rhsa_id)
    if len(result) == 0:
        return json.dumps({"err": 404, "msg": "RHSA not found"}, sort_keys=True), 404
    return json.dumps(result, sort_keys=True)


# Executes RHBA query
def _execute_rhba_query(rhba_id, details):
    regex = r"(RHBA-[0-9]{4}:[0-9]+)"
    search_obj = re.search(regex, rhba_id)
    if not search_obj or len(search_obj.group(0)) != len(rhba_id):
        return json.dumps({"err": 400, "msg": "Bad rhba format"}, sort_keys=True), 400
    if not details:
        result = InternalServer.get_mongodb_driver().get_products_by_rhba(rhba_id)
    else:
        result = InternalServer.get_mongodb_driver().get_rhba_info_by_id(rhba_id)
    if len(result) == 0:
        return json.dumps({"err": 404, "msg": "RHBA not found"}, sort_keys=True), 404
    return json.dumps(result, sort_keys=True)
