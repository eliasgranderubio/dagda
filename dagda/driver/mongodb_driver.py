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

import pymongo
import datetime
import dateutil.parser
from bson.objectid import ObjectId


class MongoDbDriver:

    # -- Public methods

    # MongoDbDriver Constructor
    def __init__(self, mongodb_host='127.0.0.1', mongodb_port=27017, mongodb_ssl=False,
                 mongodb_user=None, mongodb_pass=None):
        super(MongoDbDriver, self).__init__()
        # Prepare auth
        auth = ''
        if mongodb_user is not None and mongodb_pass is not None:
            auth = mongodb_user + ':' + mongodb_pass + '@'

        # Init
        self.client = pymongo.MongoClient('mongodb://' + auth + mongodb_host + ':' + str(mongodb_port) + '/',
                                          connect=False, ssl=mongodb_ssl)
        self.db = self.client.vuln_database

    # -- Inserting and bulk inserting methods

    # Bulk insert the cve list with the next format: <CVE-ID>#<vendor>#<product>#<version>#<year>
    def bulk_insert_cves(self, cve_list):
        products = []
        for product in cve_list:
            splitted_product = product.split("#")
            data = {}
            data['cve_id'] = splitted_product[0]
            data['vendor'] = splitted_product[1]
            data['product'] = splitted_product[2]
            data['version'] = splitted_product[3]
            data['year'] = int(splitted_product[4])
            products.append(data)
        # Bulk insert
        self.db.cve.create_index([('product', pymongo.DESCENDING)])
        self.db.cve.insert_many(products)

    # Bulk insert the cve info dict format
    def bulk_insert_cves_info(self, cves_info):
        cves = []
        for cve in cves_info:
            cves.append(cves_info[cve])
        # Bulk insert
        self.db.cve_info.create_index([('cve', pymongo.DESCENDING)], default_language='none')
        self.db.cve_info.insert_many(cves)

    # Bulk insert the bid list with the next format: <BID-ID>#<product>#<version>
    def bulk_insert_bids(self, bid_list):
        products = []
        for product in bid_list:
            splitted_product = product.split("#")
            data = {}
            data['bugtraq_id'] = int(splitted_product[0])
            data['product'] = splitted_product[1]
            data['version'] = splitted_product[2]
            products.append(data)
        # Bulk insert
        self.db.bid.create_index([('product', 'text')], default_language='none')
        self.db.bid.insert_many(products)

    # Bulk insert the exploit_db list with the next format: <EXPLOIT_DB-ID>#<product>#<version>
    def bulk_insert_exploit_db_ids(self, exploit_db_list):
        products = []
        for product in exploit_db_list:
            splitted_product = product.split("#")
            data = {}
            data['exploit_db_id'] = int(splitted_product[0])
            data['product'] = splitted_product[1]
            data['version'] = splitted_product[2]
            products.append(data)
        # Bulk insert
        self.db.exploit_db.create_index([('product', 'text')], default_language='none')
        self.db.exploit_db.insert_many(products)

    # Bulk insert the bid info list
    def bulk_insert_bid_info(self, bid_info_list):
        # Bulk insert
        self.db.bid_info.create_index([('bugtraq_id', pymongo.DESCENDING)])
        self.db.bid_info.insert_many(bid_info_list)

    # Bulk insert the exploit_db info list
    def bulk_insert_exploit_db_info(self, exploit_db_info_list):
        # Bulk insert
        self.db.exploit_db_info.create_index([('exploit_db_id', pymongo.DESCENDING)])
        self.db.exploit_db_info.insert_many(exploit_db_info_list)

    # Bulk insert the rhsa list
    def bulk_insert_rhsa(self, rhsa_list):
        # Bulk insert
        self.db.rhsa.create_index([('product', pymongo.DESCENDING)])
        self.db.rhsa.insert_many(rhsa_list)

    # Bulk insert the rhba list
    def bulk_insert_rhba(self, rhba_list):
        # Bulk insert
        self.db.rhba.create_index([('product', pymongo.DESCENDING)])
        self.db.rhba.insert_many(rhba_list)

    # Bulk insert the rhsa info list
    def bulk_insert_rhsa_info(self, rhsa_info_list):
        # Bulk insert
        self.db.rhsa_info.create_index([('rhsa_id', pymongo.DESCENDING)])
        self.db.rhsa_info.insert_many(rhsa_info_list)

    # Bulk insert the rhba info list
    def bulk_insert_rhba_info(self, rhba_info_list):
        # Bulk insert
        self.db.rhba_info.create_index([('rhba_id', pymongo.DESCENDING)])
        self.db.rhba_info.insert_many(rhba_info_list)

    # Bulk insert the sysdig/falco events
    def bulk_insert_sysdig_falco_events(self, events):
        sysdig_falco_events = []
        for event in events:
            data = {}
            data['container_id'] = event['container_id']
            data['image_name'] = event['image_name']
            data['priority'] = event['priority']
            data['time'] = dateutil.parser.parse(event['time']).timestamp()
            data['rule'] = event['rule']
            data['output'] = event['output']
            sysdig_falco_events.append(data)
        # Bulk insert
        if self.db.falco_events.count() == 0:
            self.db.falco_events.create_index([('container_id', pymongo.DESCENDING)])
        self.db.falco_events.insert_many(sysdig_falco_events)

    # Inserts the docker image scan result to history
    def insert_docker_image_scan_result_to_history(self, scan_result):
        if self.db.image_history.count() == 0:
            self.db.image_history.create_index([('image_name', pymongo.DESCENDING)])
        return self.db.image_history.insert(scan_result)

    # Updates the docker image scan result to history
    def update_docker_image_scan_result_to_history(self, id, scan_result):
        scan_result['_id'] = ObjectId(id)
        self.db.image_history.update({'_id': ObjectId(id)}, scan_result)

    # Inserts the init db process status
    def insert_init_db_process_status(self, status):
        self.db.init_db_process_status.insert(status)

    # -- Removing methods

    # Removes only the cves for updating and return the first year for inserting again
    def remove_only_cve_for_update(self):
        if "cve" not in self.db.collection_names() or self.db.cve.count() == 0:
            return 2002
        else:
            last_year_stored = self.db.cve.find({}, {'cve_id': 0, 'product': 0, 'version': 0, 'vendor': 0, '_id': 0})\
                                          .sort('year', pymongo.DESCENDING).limit(1)
            last_year = last_year_stored[0]['year'] - 1
            if last_year <= 2002:
                self.db.cve.drop()
                self.db.cve_info.drop()
                return 2002
            else:
                self.db.cve.remove({'year': {'$gte': last_year}})
                self.db.cve_info.remove({'cveid': {'$regex': 'CVE-' + str(last_year) + '-*'}})
                self.db.cve_info.remove({'cveid': {'$regex': 'CVE-' + str(last_year + 1) + '-*'}})
                return last_year

    # Removes exploit_db collection
    def delete_exploit_db_collection(self):
        self.db.exploit_db.drop()

    # Removes exploit_db info collection
    def delete_exploit_db_info_collection(self):
        self.db.exploit_db_info.drop()

    # Removes bid collection
    def delete_bid_collection(self):
        self.db.bid.drop()

    # Removes bid info collection
    def delete_bid_info_collection(self):
        self.db.bid_info.drop()

    # Removes rhsa collection
    def delete_rhsa_collection(self):
        self.db.rhsa.drop()

    # Removes rhsa info collection
    def delete_rhsa_info_collection(self):
        self.db.rhsa_info.drop()

    # Removes rhba collection
    def delete_rhba_collection(self):
        self.db.rhba.drop()

    # Removes rhba info collection
    def delete_rhba_info_collection(self):
        self.db.rhba_info.drop()

    # Removes falco_events collection
    def delete_falco_events_collection(self):
        self.db.falco_events.drop()

    # -- Querying methods

    # Gets the max bid inserted
    def get_max_bid_inserted(self):
        if "bid" not in self.db.collection_names() or self.db.bid.count() == 0:
            return 0
        else:
            last_bid = self.db.bid.find({}, {'product': 0, 'version': 0, '_id': 0})\
                                  .sort('bugtraq_id', pymongo.DESCENDING).limit(1)
            return last_bid[0]['bugtraq_id']

    # Gets the product vulnerabilities
    def get_vulnerabilities(self, product, version=None):
        filt_prod = product.replace("-", " ").replace("_", " ")
        if not version:
            # Gets CVEs
            cve_cursor = self.db.cve.find({'product': product}, {'product': 0, 'version': 0, '_id': 0})\
                                    .sort("cve_id", pymongo.ASCENDING)
            # Gets BugTraqs
            bid_cursor = self.db.bid.find({'$text': {'$search': filt_prod, '$language': 'none'}},
                                          {'product': 0, 'version': 0, '_id': 0})\
                                    .sort("bugtraq_id", pymongo.ASCENDING)
            # Gets Exploits
            exploit_db_cursor = self.db.exploit_db.find({'$text': {'$search': filt_prod, '$language': 'none'}},
                                                        {'product': 0, 'version': 0, '_id': 0})\
                                                  .sort("exploit_db_id", pymongo.ASCENDING)
            # Gets RHSAs
            rhsa_cursor = self.db.rhsa.find({'product': product}, {'product': 0, 'version': 0, '_id': 0}) \
                                      .sort("rhsa_id", pymongo.ASCENDING)
            # Gets RHBAs
            rhba_cursor = self.db.rhba.find({'product': product}, {'product': 0, 'version': 0, '_id': 0}) \
                                      .sort("rhba_id", pymongo.ASCENDING)
        else:
            # Gets CVEs
            cve_cursor = self.db.cve.find({'product': product, 'version': version},
                                          {'product': 0, 'version': 0, '_id': 0})\
                                    .sort("cve_id", pymongo.ASCENDING)
            # Gets BugTraqs
            bid_cursor = self.db.bid.find({'$text': {'$search': filt_prod, '$language': 'none'}, 'version': version},
                                          {'product': 0, 'version': 0, '_id': 0})\
                                    .sort("bugtraq_id", pymongo.ASCENDING)
            # Gets Exploits
            exploit_db_cursor = self.db.exploit_db.find({'$text': {'$search': filt_prod, '$language': 'none'},
                                                         'version': version},
                                                        {'product': 0, 'version': 0, '_id': 0})\
                                                  .sort("exploit_db_id", pymongo.ASCENDING)
            # Gets RHSAs
            rhsa_cursor = self.db.rhsa.find({'product': product, 'version': version}, \
                                            {'product': 0, 'version': 0, '_id': 0}) \
                                      .sort("rhsa_id", pymongo.ASCENDING)
            # Gets RHBAs
            rhba_cursor = self.db.rhba.find({'product': product, 'version': version}, \
                                            {'product': 0, 'version': 0, '_id': 0}) \
                                    .sort("rhba_id", pymongo.ASCENDING)

        # Prepare output
        output = []
        included_cve = []
        for cve in cve_cursor:
            if cve is not None:
                cve_temp = cve['cve_id']
                if cve_temp not in included_cve:
                    info = {}
                    cve_info = {}
                    cve_data = self.db.cve_info.find_one({'cveid': cve_temp})
                    if cve_data is not None:
                        # delte objectid and convert datetime to str
                        cve_info = cve_data.copy()
                        cve_info['mod_date'] = cve_data['mod_date'].strftime('%d-%m-%Y')
                        cve_info['pub_date'] = cve_data['pub_date'].strftime('%d-%m-%Y')
                        del cve_info["_id"]
                    info[cve_temp] = cve_info
                    output.append(info)
                    included_cve.append(cve['cve_id'])
        included_bid = []
        for bid in bid_cursor:
            if bid is not None:
                bid_tmp = 'BID-' + str(bid['bugtraq_id'])
                if bid_tmp not in included_bid:
                    info = {}
                    bid_info = {}
                    bid_data = self.db.bid_info.find_one({'bugtraq_id': bid['bugtraq_id']})
                    if bid_data is not None:
                        # delte objectid
                        bid_info = bid_data.copy()
                        del bid_info["_id"]
                    info[bid_tmp] = bid_info
                    output.append(info)
                    included_bid.append(bid_tmp)
        included_exploit = []
        for exploit_db in exploit_db_cursor:
            if exploit_db is not None:
                exploit_db_tmp = 'EXPLOIT_DB_ID-' + str(exploit_db['exploit_db_id'])
                if exploit_db_tmp not in included_exploit:
                    info = {}
                    exploit_db_info = {}
                    exploit_data = self.db.exploit_db_info.find_one({'exploit_db_id': exploit_db['exploit_db_id']})
                    if exploit_data is not None:
                        # delte objectid
                        exploit_db_info = exploit_data.copy()
                        del exploit_db_info["_id"]
                    info[exploit_db_tmp] = exploit_db_info
                    output.append(info)
                    included_exploit.append(exploit_db_tmp)
        included_rhsa = []
        for rhsa in rhsa_cursor:
            if rhsa is not None:
                rhsa_temp = rhsa['rhsa_id']
                if rhsa_temp not in included_rhsa:
                    info = {}
                    rhsa_info = {}
                    rhsa_data = self.db.rhsa_info.find_one({'rhsa_id': rhsa['rhsa_id']})
                    if rhsa_data is not None:
                        # delte objectid
                        rhsa_info = rhsa_data.copy()
                        del rhsa_info["_id"]
                    info[rhsa_temp] = rhsa_info
                    output.append(info)
                    included_rhsa.append(rhsa_temp)
        included_rhba = []
        for rhba in rhba_cursor:
            if rhba is not None:
                rhba_temp = rhba['rhba_id']
                if rhba_temp not in included_rhba:
                    info = {}
                    rhba_info = {}
                    rhba_data = self.db.rhba_info.find_one({'rhba_id': rhba['rhba_id']})
                    if rhba_data is not None:
                        # delte objectid
                        rhba_info = rhba_data.copy()
                        del rhba_info["_id"]
                    info[rhba_temp] = rhba_info
                    output.append(info)
                    included_rhsa.append(rhba_temp)
        # Return
        return output

    # Gets products by CVE
    def get_products_by_cve(self, cve):
        cursor = self.db.cve.find({'cve_id': cve}, {'cve_id': 0, '_id': 0}).sort([("product", pymongo.ASCENDING),
                                                                                  ("version", pymongo.ASCENDING)])
        # Prepare output
        output = []
        for product in cursor:
            if product is not None:
                output.append(product)
        # Return
        return output

    # Gets products by BID
    def get_products_by_bid(self, bid):
        cursor = self.db.bid.find({'bugtraq_id': bid}, {'bugtraq_id': 0, '_id': 0}).sort(
            [("product", pymongo.ASCENDING), ("version", pymongo.ASCENDING)])
        # Prepare output
        output = []
        for product in cursor:
            if product is not None:
                output.append(product)
        # Return
        return output

    # Gets products by Exploit_db id
    def get_products_by_exploit_db_id(self, exploit_db_id):
        cursor = self.db.exploit_db.find({'exploit_db_id': exploit_db_id}, {'exploit_db_id': 0, '_id': 0}).sort(
            [("product", pymongo.ASCENDING), ("version", pymongo.ASCENDING)])
        # Prepare output
        output = []
        for product in cursor:
            if product is not None:
                output.append(product)
        # Return
        return output

    # Gets products by RHSA
    def get_products_by_rhsa(self, rhsa):
        cursor = self.db.rhsa.find({'rhsa_id': rhsa}, {'rhsa_id': 0, '_id': 0}).sort([("product", pymongo.ASCENDING),
                                                                                      ("version", pymongo.ASCENDING)])
        # Prepare output
        output = []
        for product in cursor:
            if product is not None:
                output.append(product)
        # Return
        return output

    # Gets products by RHBA
    def get_products_by_rhba(self, rhba):
        cursor = self.db.rhba.find({'rhba_id': rhba}, {'rhba_id': 0, '_id': 0}).sort([("product", pymongo.ASCENDING),
                                                                                      ("version", pymongo.ASCENDING)])
        # Prepare output
        output = []
        for product in cursor:
            if product is not None:
                output.append(product)
        # Return
        return output

    # Gest CVE description by id
    def get_cve_info_by_cve_id(self, cve_id):
        cursor = self.db.cve_info.find({'cveid': cve_id}).sort(
            [("cves", pymongo.ASCENDING), ("cvss_base", pymongo.ASCENDING)])
        # Prepare output
        output = []
        for info in cursor:
            if info is not None:
                # delete objectid and convert datetime to str
                del info['_id']
                info['mod_date']=info['mod_date'].strftime('%d-%m-%Y')
                info['pub_date']=info['pub_date'].strftime('%d-%m-%Y')
                output.append(info)
        # Return
        return output

    # Gets BugTraq description by id
    def get_bid_info_by_id(self, bid_id):
        cursor = self.db.bid_info.find({'bugtraq_id': bid_id}).sort([("bugtraq_id", pymongo.ASCENDING)])
        # Prepare output
        output = []
        for info in cursor:
            if info is not None:
                # delete objectid
                del info['_id']
                output.append(info)
        # Return
        return output

    # Gets Exploit description by id
    def get_exploit_info_by_id(self, exploit_db_id):
        cursor = self.db.exploit_db_info.find({'exploit_db_id': exploit_db_id}).sort(
            [("exploit_db_id", pymongo.ASCENDING)])
        # Prepare output
        output = []
        for info in cursor:
            if info is not None:
                # delete objectid
                del info['_id']
                output.append(info)
        # Return
        return output

    # Gets RHSA description by id
    def get_rhsa_info_by_id(self, rhsa_id):
        cursor = self.db.rhsa_info.find({'rhsa_id': rhsa_id}).sort([("rhsa_id", pymongo.ASCENDING)])
        # Prepare output
        output = []
        for info in cursor:
            if info is not None:
                # delete objectid
                del info['_id']
                output.append(info)
        # Return
        return output

    # Gets RHBA description by id
    def get_rhba_info_by_id(self, rhba_id):
        cursor = self.db.rhba_info.find({'rhba_id': rhba_id}).sort([("rhba_id", pymongo.ASCENDING)])
        # Prepare output
        output = []
        for info in cursor:
            if info is not None:
                # delete objectid
                del info['_id']
                output.append(info)
        # Return
        return output

    # Gets docker specific image history
    def get_docker_image_history(self, image_name, id=None):
        if not id:
            cursor = self.db.image_history.find({'image_name': image_name}).sort("timestamp", pymongo.DESCENDING)
        else:
            cursor = self.db.image_history.find({'image_name': image_name, '_id': ObjectId(id)})\
                                          .sort("timestamp", pymongo.DESCENDING)

        # Prepare output
        output = []
        for scan in cursor:
            if scan is not None:
                if 'runtime_analysis' in scan:
                    if self.is_there_a_started_monitoring(scan['runtime_analysis']['container_id']):
                        self.update_runtime_monitoring_analysis(scan['runtime_analysis']['container_id'])
                        scan = self.get_a_started_monitoring(scan['runtime_analysis']['container_id'])
                    scan['runtime_analysis']['start_timestamp'] = \
                        str(datetime.datetime.utcfromtimestamp(
                            scan['runtime_analysis']['start_timestamp']))
                    if scan['runtime_analysis']['stop_timestamp'] is not None:
                        scan['runtime_analysis']['stop_timestamp'] = \
                            str(datetime.datetime.utcfromtimestamp(scan['runtime_analysis']['stop_timestamp']))
                scan['id'] = str(scan['_id'])
                del scan['_id']
                scan['timestamp'] = str(datetime.datetime.utcfromtimestamp(scan['timestamp']))
                output.append(scan)
        # Return
        return output

    # Gets all docker images history
    def get_docker_image_all_history(self):
        cursor = self.db.image_history.find({}).sort("timestamp", pymongo.DESCENDING)

        # Prepare output
        output = []
        for scan in cursor:
            if scan is not None:
                report = {}
                report['reportid'] = str(scan['_id'])
                report['image_name'] = scan['image_name']

                # Gets status info
                if 'status' in scan:
                    report['status'] = scan['status']
                else:
                    report['status'] = 'Unknown'

                report['start_date'] = str(datetime.datetime.utcfromtimestamp(scan['timestamp']))
                report['malware_bins'] = 0
                report['os_vulns'] = 0
                report['libs_vulns'] = 0
                report['anomalies'] = 0

                # Gets static analysis info
                if 'static_analysis' in scan:
                    if 'os_packages' in scan['static_analysis']:
                        report['os_vulns'] = scan['static_analysis']['os_packages']['vuln_os_packages']
                    if 'malware_binaries' in scan['static_analysis']:
                        report['malware_bins'] = len(scan['static_analysis']['malware_binaries'])
                    if 'prog_lang_dependencies' in scan['static_analysis']:
                        report['libs_vulns'] = scan['static_analysis']['prog_lang_dependencies']['vuln_dependencies']

                # Gets runtime analysis info
                if 'runtime_analysis' in scan and scan['runtime_analysis'] is not None and \
                   'anomalous_activities_detected' in scan['runtime_analysis'] and \
                    scan['runtime_analysis']['anomalous_activities_detected'] is not None and \
                   'anomalous_counts_by_severity' in scan['runtime_analysis']['anomalous_activities_detected'] and \
                    scan['runtime_analysis']['anomalous_activities_detected']['anomalous_counts_by_severity'] is not None:
                        anomalous_counts = sum(scan['runtime_analysis']['anomalous_activities_detected']
                                               ['anomalous_counts_by_severity'].values())
                        report['anomalies'] = anomalous_counts
                output.append(report)
        # Return
        return output

    # Check if product vulnerability was tagged as false positive
    def is_fp(self, image_name, product, version=None):
        cursor = self.db.image_history.find({'image_name': image_name}).sort("timestamp", pymongo.DESCENDING)
        for scan in cursor:
            if scan is not None and 'status' in scan and 'Completed' in scan['status'] and 'static_analysis' in scan:
                # OS packages
                if 'os_packages' in scan['static_analysis']:
                    for p in scan['static_analysis']['os_packages']['os_packages_details']:
                        if p['product'] == product and (version is None or p['version'] == version):
                            if 'is_false_positive' in p and p['is_false_positive']:
                                return True

                # Dependencies
                if 'prog_lang_dependencies' in scan['static_analysis'] and \
                        scan['static_analysis']['prog_lang_dependencies']['dependencies_details'] is not None:
                    for language in ['java', 'python', 'nodejs', 'js', 'ruby', 'php']:
                        if scan['static_analysis']['prog_lang_dependencies']['dependencies_details']\
                                [language] is not None:
                            for p in scan['static_analysis']['prog_lang_dependencies']['dependencies_details']\
                                    [language]:
                                if p['product'] == product and (version is None or p['version'] == version):
                                    if 'is_false_positive' in p and p['is_false_positive']:
                                        return True
                break

        # Default
        return False

    # Update product vulnerability as false positive
    def update_product_vulnerability_as_fp(self, image_name, product, version=None):
        cursor = self.db.image_history.find({'image_name': image_name}).sort("timestamp", pymongo.DESCENDING)
        updated = False
        for scan in cursor:
            if scan is not None and 'status' in scan and 'Completed' in scan['status'] and 'static_analysis' in scan:
                # OS packages
                if 'os_packages' in scan['static_analysis']:
                    updated_products = 0
                    for p in scan['static_analysis']['os_packages']['os_packages_details']:
                        if p['product'] == product and (version is None or p['version'] == version):
                            if not p['is_false_positive']:
                                p['is_false_positive'] = True
                                updated_products += 1
                                updated = True
                    scan['static_analysis']['os_packages']['vuln_os_packages'] -= updated_products
                    scan['static_analysis']['os_packages']['ok_os_packages'] += updated_products

                # Dependencies
                if 'prog_lang_dependencies' in scan['static_analysis'] and \
                        scan['static_analysis']['prog_lang_dependencies']['dependencies_details'] is not None:
                    updated_dependencies = 0
                    for language in ['java', 'python', 'nodejs', 'js', 'ruby', 'php']:
                        if scan['static_analysis']['prog_lang_dependencies']['dependencies_details']\
                                [language] is not None:
                            for p in scan['static_analysis']['prog_lang_dependencies']['dependencies_details']\
                                    [language]:
                                if p['product'] == product and (version is None or p['version'] == version):
                                    if not p['is_false_positive']:
                                        p['is_false_positive'] = True
                                        updated_dependencies += 1
                                        updated = True
                    scan['static_analysis']['prog_lang_dependencies']['vuln_dependencies'] -= \
                                                                                            updated_dependencies

                # Update collection
                self.db.image_history.update({'_id': scan['_id']}, scan)
                break

        # Return if the scan was updated or not
        return updated

    # Gets the init db process status
    def get_init_db_process_status(self):
        cursor = self.db.init_db_process_status.find({}, {'_id': 0}).sort("timestamp", pymongo.DESCENDING)
        for status in cursor:
            if status is not None:
                return status
        return {'status': 'None', 'timestamp': None}

    # Gets if there is a started monitoring for a concrete container id
    def is_there_a_started_monitoring(self, container_id):
        return self.db.image_history.count({'runtime_analysis.container_id': container_id,
                                            'status': 'Monitoring'}) != 0

    # Gets a started monitoring for a concrete container id
    def get_a_started_monitoring(self, container_id):
        return self.db.image_history.find_one({'runtime_analysis.container_id': container_id,
                                               'status': 'Monitoring'})

    # Updates the runtime analysis field
    def update_runtime_monitoring_analysis(self, container_id):
        image_history = self.db.image_history.find_one({'runtime_analysis.container_id': container_id,
                                                        'status': 'Monitoring'})
        # -- Process falco events
        if image_history:
            events = []
            priorities = []
            start_timestamp = image_history['runtime_analysis']['start_timestamp']
            cursor = self.db.falco_events.find({'container_id': container_id[:12],
                                                'image_name': image_history['image_name'],
                                                'time': {'$gte': start_timestamp}})
            for event in cursor:
                if event is not None:
                    del event['container_id']
                    del event['image_name']
                    del event['_id']
                    event['time'] = str(datetime.datetime.utcfromtimestamp(event['time']))
                    events.append(event)
                    priorities.append(event['priority'])

            # Prepare anomalous_activities_detected field
            if len(events) > 0:
                anomalous_activities_detected = self._generate_anomalous_activities_detected_field(events, priorities)
                image_history['runtime_analysis']['anomalous_activities_detected'] = anomalous_activities_detected
                # -- Update history
                self.update_docker_image_scan_result_to_history(str(image_history['_id']), image_history)

    # -- Private methods

    # Generates the anomalous_activities_detected field
    def _generate_anomalous_activities_detected_field(self, events, priorities):
        data = {}
        data['anomalous_counts_by_severity'] = {}
        data['anomalous_activities_details'] = []
        for priority in priorities:
            try:
                data['anomalous_counts_by_severity'][priority] = data['anomalous_counts_by_severity'][priority] + 1
            except KeyError:
                data['anomalous_counts_by_severity'][priority] = 1
        for event in events:
            data['anomalous_activities_details'].append(event)
        return data
