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
from io import BytesIO
import datetime
import tarfile


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
def extract_vector(initial_vector):
    new_vector = initial_vector[1:-1].split('/')
    final_vector = []
    for i in range(len(new_vector)):
        final_vector.append(FEATURES_LIST[i][new_vector[i][-1]])
    return new_vector, final_vector


# Gets CVE list from compressed file
def get_cve_list_from_file(compressed_content, year):
    cve_set = set()
    cve_info_list = []
    json_file_content = zlib.decompress(compressed_content, 16 + zlib.MAX_WBITS)
    for cve in json.loads(json_file_content)['CVE_Items']:
        cve_id = cve['cve']['CVE_data_meta']['ID']
        for node in cve['configurations']['nodes']:
            def get_cpe_match(node, cve_id, year):
                output_set = set()
                if 'children' in node:
                    for child in node['children']:
                        temp_set = get_cpe_match(child, cve_id, year)
                        output_set = output_set.union(temp_set)
                if 'cpe_match' in node:
                    for cpe in node['cpe_match']:
                        splitted_product = cpe['cpe23Uri'].replace('\\#', " ").split(":")
                        if len(splitted_product) > 4:
                            item = cve_id + "#" + splitted_product[3] + "#" + splitted_product[4] + "#" + \
                                   splitted_product[5] + "#" + str(year)
                            output_set.add(item)
                return output_set
            cve_set = cve_set.union(get_cpe_match(node, cve_id, year))

        # Get CVE info
        try:
            cveid = cve_id
            aux = cve['publishedDate'].split('T')[0].split('-')
            pub_date = datetime.datetime(int(aux[0]), int(aux[1]), int(aux[2]))
            aux = cve['lastModifiedDate'].split('T')[0].split('-')
            mod_date = datetime.datetime(int(aux[0]), int(aux[1]), int(aux[2]))
            cvss_base = float(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])
            cvss_impact = float(cve['impact']['baseMetricV2']['impactScore'])
            cvss_exploit = float(cve['impact']['baseMetricV2']['exploitabilityScore'])
            vector = cve['impact']['baseMetricV2']['cvssV2']['vectorString']
            access_vector = cve['impact']['baseMetricV2']['cvssV2']['accessVector']
            access_complexity = cve['impact']['baseMetricV2']['cvssV2']['accessComplexity']
            authentication = cve['impact']['baseMetricV2']['cvssV2']['authentication']
            confidentiality_impact = cve['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
            integrity_impact = cve['impact']['baseMetricV2']['cvssV2']['integrityImpact']
            availability_impact = cve['impact']['baseMetricV2']['cvssV2']['availabilityImpact']
            summary = cve['cve']['description']['description_data'][0]['value']
            cweid = ''
            try:
                cweid = cve['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
            except IndexError:
                pass
            cve_info = {
                "cveid": cveid,
                "pub_date": pub_date,
                "mod_date": mod_date,
                "summary": summary,
                "cvss_base": cvss_base,
                "cvss_impact": cvss_impact,
                "cvss_exploit": cvss_exploit,
                "cvss_access_vector": access_vector,
                "cvss_access_complexity": access_complexity,
                "cvss_authentication": authentication,
                "cvss_confidentiality_impact": confidentiality_impact,
                "cvss_integrity_impact": integrity_impact,
                "cvss_availability_impact": availability_impact,
                "cvss_vector": vector,
                "cweid": cweid
            }
            cve_info_list.append(cve_info)
        except KeyError:
            # Any error continue
            pass

    return list(cve_set), cve_info_list


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
                    details['platform'] = splitted_line[6] if splitted_line[6] is not None else ''
                    details['type'] = splitted_line[5] if splitted_line[5] is not None else ''
                    try:
                        details['port'] = int(splitted_line[7])
                    except ValueError:
                        details['port'] = 0
                    exploits_details.append(details)
    # Return
    return list(items), exploits_details


# Gets BugTraq lists from gz file
def get_bug_traqs_lists_from_file(compressed_file):
    decompressed_file = gzip.GzipFile(fileobj=compressed_file)
    bid_list = [line.decode("utf-8") for line in decompressed_file.readlines()]
    return get_bug_traqs_lists_from_online_mode(bid_list)


# Gets BugTraq lists from online mode
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
        except (TypeError, ValueError):
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


# Gets RHSA (Red Hat Security Advisory) and RHBA (Red Hat Bug Advisory) lists from bz2 file
def get_rhsa_and_rhba_lists_from_file(bz2_file):
    # Init
    tar = tarfile.open(mode='r:bz2', fileobj=BytesIO(bz2_file))
    rhsa_list = []
    rhsa_id_list = []
    rhba_list = []
    rhba_id_list = []
    rhsa_info_list = []
    rhsa_info_id_list = []
    rhba_info_list = []
    rhba_info_id_list = []
    for xml_file in tar.getmembers():
        if xml_file.size > 0:
            xml_file_content = tar.extractfile(xml_file.name)
            root = ET.parse(xml_file_content).getroot().find('{http://oval.mitre.org/XMLSchema/oval-definitions-5}definitions')
            for entry in root.findall('{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition'):
                # Init
                metadata = entry.find('{http://oval.mitre.org/XMLSchema/oval-definitions-5}metadata')
                detail_info = {}

                # Get IDs
                rhsa_id = None
                rhba_id = None
                cves = []
                for reference in metadata.findall("{http://oval.mitre.org/XMLSchema/oval-definitions-5}reference"):
                    # Get RHSA (Red Hat Security Advisory)
                    if 'RHSA' in reference.attrib['ref_id']:
                        rhsa_id = reference.attrib['ref_id']
                        if "-" in rhsa_id[5:]:
                            rhsa_id = rhsa_id[:rhsa_id.index("-", 5)]
                    # RHBA (Red Hat Bug Advisory)
                    if 'RHBA' in reference.attrib['ref_id']:
                        rhba_id = reference.attrib['ref_id']
                        if "-" in rhba_id[5:]:
                            rhba_id = rhba_id[:rhba_id.index("-", 5)]
                    # Get related CVEs
                    if reference.attrib['source'] == 'CVE':
                        cves.append(reference.attrib['ref_id'])

                detail_info['cve'] = cves

                # Get title and description
                detail_info['title'] = metadata.findtext('{http://oval.mitre.org/XMLSchema/oval-definitions-5}title')
                detail_info['description'] = metadata.findtext('{http://oval.mitre.org/XMLSchema/oval-definitions-5}description')

                # Get severity
                detail_info['severity'] = metadata.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}advisory") \
                                                    .find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}severity").text
                # Append detail info
                if rhsa_id is not None:
                    detail_info['rhsa_id'] = rhsa_id
                    if rhsa_id not in rhsa_info_id_list:
                        rhsa_info_id_list.append(rhsa_id)
                        rhsa_info_list.append(detail_info)
                if rhba_id is not None:
                    detail_info['rhba_id'] = rhba_id
                    if rhba_id not in rhba_info_id_list:
                        rhba_info_id_list.append(rhba_id)
                        rhba_info_list.append(detail_info)

                # Get vulnerable products
                affected_cpe_list = metadata.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}advisory") \
                                            .find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}affected_cpe_list")
                for cpe in affected_cpe_list:
                  if cpe.text is not None:
                    info_item = {}
                    splitted_product = cpe.text.split(":")
                    info_item['vendor'] = splitted_product[2]
                    info_item['product'] = splitted_product[3]
                    try:
                        info_item['version'] = splitted_product[4]
                    except IndexError:
                        info_item['version'] = '-'

                    tmp = '#' + info_item['vendor'] + '#' + info_item['product'] + '#' + info_item['version']
                    if rhsa_id is not None:
                        info_item['rhsa_id'] = rhsa_id
                        tmp = rhsa_id + tmp
                        if tmp not in rhsa_id_list:
                            rhsa_id_list.append(tmp)
                            rhsa_list.append(info_item)
                    if rhba_id is not None:
                        info_item['rhba_id'] = rhba_id
                        tmp = rhba_id + tmp
                        if tmp not in rhba_id_list:
                            rhba_id_list.append(tmp)
                            rhba_list.append(info_item)

    # Return
    return rhsa_list, rhba_list, rhsa_info_list, rhba_info_list
