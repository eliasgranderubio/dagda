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

    # Bulk insert the cve list with the next format: <CVE-ID>#<vendor>#<product>#<version>
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

    # Bulk insert the exploit_db info list
    def bulk_insert_exploit_db_info(self, exploit_db_info_list):
        # Bulk insert
        self.db.exploit_db_info.create_index([('exploit_db_id', pymongo.DESCENDING)])
        self.db.exploit_db_info.insert_many(exploit_db_info_list)

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
        # Prepare output
        output = []
        for cve in cve_cursor:
            if cve is not None:
                cve_temp = cve['cve_id']
                if cve_temp not in output:
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
        for bid in bid_cursor:
            if bid is not None:
                bid_tmp = 'BID-' + str(bid['bugtraq_id'])
                if bid_tmp not in output:
                    info = {}
                    bid_info = ""
                    info[bid_tmp] = bid_info
                    output.append(info)
        for exploit_db in exploit_db_cursor:
            if exploit_db is not None:
                exploit_db_tmp = 'EXPLOIT_DB_ID-' + str(exploit_db['exploit_db_id'])
                if exploit_db_tmp not in output:
                    info = {}
                    exploit_tmp = ""
                    info[exploit_db_tmp] = exploit_tmp
                    output.append(info)
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
                report['os_vulns'] = 0
                report['libs_vulns'] = 0
                report['anomalies'] = 0

                # Gets static analysis info
                if 'static_analysis' in scan:
                    if 'os_packages' in scan['static_analysis']:
                        report['os_vulns'] = scan['static_analysis']['os_packages']['vuln_os_packages']
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
