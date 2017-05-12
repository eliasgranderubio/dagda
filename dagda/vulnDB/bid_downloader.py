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

import requests
import json
import re
from joblib import Parallel, delayed
from log.dagda_logger import DagdaLogger


# Get vulnerability title from HTML body
def get_title(body):
    init_index = body.index('<span class="title">') + len('<span class="title">')
    return body[init_index:body.index('</span>')]


# Get specific BID info
def get_info_by_label(body, label):
    init_index = body.index('<span class="label">' + label + ':</span>') + \
                 len('<span class="label">' + label + ':</span>')
    tmp_body = body[init_index:]
    init_index = tmp_body.index('<td>') + len('<td>')
    tmp_body = tmp_body[init_index:]
    tmp_body = tmp_body[:tmp_body.index('</td>')]
    return tmp_body.rstrip().lstrip()


# Get CVEs
def get_linked_CVEs(body):
    regex = r"(CVE-[0-9]{4}-[0-9]{4,5})"
    cves_obj = re.search(regex, body)
    cves = []
    if cves_obj:
       for group in cves_obj.groups():
           cves.append(group)
    return cves


# Get vulnerable products from HTML body
def get_vulnerable_products(body):
    tmp_body = get_info_by_label(body, 'Vulnerable')
    if '<span class="related">' in tmp_body:
        regex = re.compile(r"<span class=\"related\">(\n.*){5}<\/span>", re.MULTILINE)
        tmp_body = re.sub(regex, '', tmp_body)
    splitted_body = tmp_body.split('<br/>')
    vuln_products = []
    for line in splitted_body:
        line = line.rstrip().lstrip()
        if len(line) != 0:
            vuln_products.append(line)
    return vuln_products


# Prepares output
def prepare_output(title, bugtraq_id, clazz, linked_cves, is_local, is_remote, vuln_products):
    data = {}
    data['title'] = title
    data['bugtraq_id'] = bugtraq_id
    data['class'] = clazz
    data['cve'] = linked_cves
    data['local'] = is_local.lower()
    data['remote'] = is_remote.lower()
    data['vuln_products'] = vuln_products
    return data


# Requests the bid, parses the HTML and prints the BugTraq info
def get_bid(bugtraq_id):
    url = "http://www.securityfocus.com/bid/" + str(bugtraq_id)
    try:
        r = requests.get(url)
        if r.status_code == 200:
            try:
                body = r.content.decode("utf-8")
                body = body[body.index('<div id="vulnerability">'):
                            body.index('<span class="label">Not Vulnerable:</span>')]
                title = get_title(body)
                clazz = get_info_by_label(body, 'Class')
                linked_cves = get_linked_CVEs(body)
                is_local = get_info_by_label(body, 'Local')
                is_remote = get_info_by_label(body, 'Remote')
                vuln_products = get_vulnerable_products(body)
            except:
                vuln_products = []
            if len(vuln_products) > 0:
                return json.dumps(prepare_output(title, bugtraq_id, clazz, linked_cves, is_local, is_remote,
                                                 vuln_products), sort_keys=True)
    except requests.ConnectionError:
        DagdaLogger.get_logger().warning('Connection error occurred with: "' + url + '"')
        return None


# Executes the main function called get_bid in a parallel way
def bid_downloader(first_bid, last_bid):
    output_list = Parallel(n_jobs=100)(delayed(get_bid)(i) for i in range(first_bid, last_bid + 1))
    return [x for x in output_list if x is not None]
