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
import gzip
import re
import requests
import zlib
import defusedxml.ElementTree as ET
from zipfile import ZipFile
import os
from io import BytesIO
import datetime

ACCESS_VECTOR = {'L': 'Local access', 'A': 'Adjacent Network', 'N': 'Network'}
ACCESS_COMPLEXITY = {'H': 'High', 'M': 'Medium', 'L': 'Low'}
AUTHENTICATION = {'N': 'None required', 'S': 'Requires single instance', 'M': 'Requires multiple instances'}
CONFIDENTIALITY_IMPACT = {'N': 'None', 'P': 'Partial', 'C': 'Complete'}
INTEGRITY_IMPACT = {'N': 'None', 'P': 'Partial', 'C': 'Complete'}
AVAILABILITY_IMPACT = {'N': 'None', 'P': 'Partial', 'C': 'Complete'}

FEATURES_LIST = [ACCESS_VECTOR, ACCESS_COMPLEXITY, AUTHENTICATION, CONFIDENTIALITY_IMPACT, INTEGRITY_IMPACT,
                 AVAILABILITY_IMPACT]


# Gets HTTP resource content
def get_http_resource_content(url):
    r = requests.get(url)
    return r.content


# Extract vector from CVE
def extract_vector(initialVector):
    new_vector = initialVector[1:-1].split('/')
    final_vector = []
    for i in range(len(new_vector)):
        final_vector.append(FEATURES_LIST[i][new_vector[i][-1]])
    return new_vector, final_vector


# Gets CVE list from compressed file
def get_cve_list_from_file(compressed_content, year):
    cve_set = set()
    xml_file_content = zlib.decompress(compressed_content, 16 + zlib.MAX_WBITS)
    root = ET.fromstring(xml_file_content)
    for entry in root.findall("{http://scap.nist.gov/schema/feed/vulnerability/2.0}entry"):
        vuln_soft_list = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}vulnerable-software-list")
        if vuln_soft_list is not None:
            for vuln_product in vuln_soft_list.findall(
                    "{http://scap.nist.gov/schema/vulnerability/0.4}product"):
                splitted_product = vuln_product.text.split(":")
                if len(splitted_product) > 4:
                    item = entry.attrib.get("id") + "#" + splitted_product[2] + "#" + splitted_product[3] + "#" + \
                           splitted_product[4] + "#" + str(year)
                    if item not in cve_set:
                        cve_set.add(item)
    return list(cve_set)


# Gets description from CVE compresed files
def get_cve_description_from_file(compressed_content):
    cve_info_set = {}
    zip_file = ZipFile(BytesIO(compressed_content))
    filename = zip_file.extract(zip_file.filelist[0])
    root = ET.parse(filename).getroot()
    os.remove(filename)
    for child in root:
        try:
            cveid = child.attrib['name']
            aux = child.attrib['published'].split('-')
            pub_date = datetime.datetime(int(aux[0]), int(aux[1]), int(aux[2]))
            aux = child.attrib['modified'].split('-')
            mod_date = datetime.datetime(int(aux[0]), int(aux[1]), int(aux[2]))
            cvss_base = float(child.attrib['CVSS_base_score'])
            cvss_impact = float(child.attrib['CVSS_impact_subscore'])
            cvss_exploit = float(child.attrib['CVSS_exploit_subscore'])
            vector, features = extract_vector(child.attrib['CVSS_vector'])
            summary = child[0][0].text
            cve_info_set[cveid] = {"cveid": cveid,
                                    "pub_date": pub_date,
                                    "mod_date": mod_date,
                                    "summary": summary,
                                    "cvss_base": cvss_base,
                                    "cvss_impact": cvss_impact,
                                    "cvss_exploit": cvss_exploit,
                                    "cvss_access_vector": features[0],
                                    "cvss_access_complexity": features[1],
                                    "cvss_authentication": features[2],
                                    "cvss_confidentiality_impact": features[3],
                                    "cvss_integrity_impact": features[4],
                                    "cvss_availability_impact": features[5],
                                    "cvss_vector": vector,
                                    "cweid": "CWE-0"
                                    }
        except KeyError:
            # Any error continue
            pass
    return dict(cve_info_set)


# Update cweid info at cve description
def get_cve_cweid_from_file(compressed_content, cve_dict):
    zip = ZipFile(BytesIO(compressed_content))
    zip_file = ZipFile(BytesIO(compressed_content))
    filename = zip_file.extract(zip_file.filelist[0])
    root = ET.parse(filename).getroot()
    os.remove(filename)
    cwe_ns = "{http://scap.nist.gov/schema/vulnerability/0.4}"
    default_ns = "{http://scap.nist.gov/schema/feed/vulnerability/2.0}"
    for entry in root.findall('{ns}entry'.format(ns=default_ns)):
        id = entry.attrib["id"]
        cwe = entry.find('{nsd}cwe'.format(nsd=cwe_ns))
        if cwe is not None:
            if id in cve_dict.keys():
                cve_dict[id]["cweid"] = str(cwe.attrib["id"])
    return dict(cve_dict)


# Gets Exploit_db list from csv file
def get_exploit_db_list_from_csv(csv_content):
    items = set()
    exploits_details = []
    for line in csv_content.split("\n"):
        item_added = False
        splitted_line = line.split(',')
        if splitted_line[0] != 'id' and len(splitted_line) > 3:
            exploit_db_id = splitted_line[0]
            description = splitted_line[2][1:len(splitted_line[2]) - 1]
            if '-' in description:
                description = description[0:description.index('-')].lstrip().rstrip().lower()
                iterator = re.finditer("([0-9]+(\.[0-9]+)+)", description)
                match = next(iterator, None)
                if match:
                    version = match.group()
                    description = description[:description.index(version)].rstrip().lstrip()
                    item = str(exploit_db_id) + "#" + description + "#" + str(version)
                    if item not in items:
                        items.add(item)
                        item_added = True
                    for match in iterator:
                        version = match.group()
                        item = str(exploit_db_id) + "#" + description + "#" + str(version)
                        if item not in items:
                            items.add(item)
                            item_added = True
                else:
                    if '<' not in description and '>' not in description:
                        iterator = re.finditer("\s([0-9])+$", description)
                        match = next(iterator, None)
                        if match:
                            version = match.group()
                            description = description[:description.index(version)].rstrip().lstrip()
                            version = version.rstrip().lstrip()
                            item = str(exploit_db_id) + "#" + description + "#" + str(version)
                            if item not in items:
                                items.add(item)
                                item_added = True
                # Generate exploit details
                if item_added:
                    details = {}
                    details['exploit_db_id'] = int(splitted_line[0])
                    details['description'] = splitted_line[2][1:len(splitted_line[2]) - 1]
                    details['platform'] = splitted_line[5] if splitted_line[5] is not None else ''
                    details['type'] = splitted_line[6] if splitted_line[6] is not None else ''
                    details['port'] = int(splitted_line[7]) if splitted_line[7] is not None else 0
                    exploits_details.append(details)
    # Return
    return list(items), exploits_details


# Gets BugTraq lists from gz file
def get_bug_traqs_lists_from_file(compressed_file):
    decompressed_file = gzip.GzipFile(fileobj=compressed_file)
    items = set()
    output_array = []
    extended_info_array = []
    for line in decompressed_file.readlines():
        try:
            json_data = json.loads(line.decode("utf-8"))
            parse_bid_from_json(json_data, items)
            del json_data['vuln_products']
            extended_info_array.append(json_data)
        except (TypeError, json.JSONDecodeError):
            # It is not a JSON format so the line is ignored
            pass
        # Bulk insert
        if len(items) > 8000:
            output_array.append(list(items))
            items = set()
    # Final bulk insert
    if len(items) > 0:
        output_array.append(list(items))
    # Return
    return output_array, extended_info_array


# Gets BugTraq lists from gz file
def get_bug_traqs_lists_from_online_mode(bid_list):
    items = set()
    output_array = []
    extended_info_array = []
    for line in bid_list:
        try:
            json_data = json.loads(line)
            parse_bid_from_json(json_data, items)
            del json_data['vuln_products']
            extended_info_array.append(json_data)
        except (TypeError, json.JSONDecodeError):
            # It is not a JSON format so the line is ignored
            pass
        # Bulk insert
        if len(items) > 8000:
            output_array.append(list(items))
            items = set()
    # Final bulk insert
    if len(items) > 0:
        output_array.append(list(items))
    # Return
    return output_array, extended_info_array


# Parses BID from json data
def parse_bid_from_json(json_data, items):
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
