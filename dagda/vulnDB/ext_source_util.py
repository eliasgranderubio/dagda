import json
import gzip
import re
import requests
import zlib
import xml.etree.ElementTree as ET


# Gets HTTP resource content
def get_http_resource_content(url):
    r = requests.get(url)
    return r.content


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


# Gets Exploit_db list from csv file
def get_exploit_db_list_from_csv(csv_content):
    items = set()
    for line in csv_content.split("\n"):
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
                    for match in iterator:
                        version = match.group()
                        item = str(exploit_db_id) + "#" + description + "#" + str(version)
                        if item not in items:
                            items.add(item)
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
    # Return
    return list(items)


# Gets BugTraq lists from gz file
def get_bug_traqs_lists_from_file(compressed_file):
    decompressed_file = gzip.GzipFile(fileobj=compressed_file)
    items = set()
    output_array = []
    for line in decompressed_file.readlines():
        try:
            json_data = json.loads(line.decode("utf-8"))
            parse_bid_from_json(json_data, items)
        except:
            None
        # Bulk insert
        if len(items) > 8000:
            output_array.append(list(items))
            items = set()
    # Final bulk insert
    if len(items) > 0:
        output_array.append(list(items))
    # Return
    return output_array


# Gets BugTraq lists from gz file
def get_bug_traqs_lists_from_online_mode(bid_list):
    items = set()
    output_array = []
    for line in bid_list:
        try:
            json_data = json.loads(line)
            parse_bid_from_json(json_data, items)
        except:
            None
        # Bulk insert
        if len(items) > 8000:
            output_array.append(list(items))
            items = set()
    # Final bulk insert
    if len(items) > 0:
        output_array.append(list(items))
    # Return
    return output_array


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
