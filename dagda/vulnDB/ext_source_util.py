import requests
import zlib
import xml.etree.ElementTree as ET


# Gets HTTP resource content
def get_http_resource_content(url):
    r = requests.get(url)
    return r.content


# Gets CVE list from compressed file
def get_cve_list_from_file(compressed_content):
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
                           splitted_product[4]
                    if item not in cve_set:
                        cve_set.add(item)
    return list(cve_set)
