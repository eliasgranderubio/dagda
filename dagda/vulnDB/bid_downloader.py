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


# Get vulnerability title from HTML body
def get_title(body):
    init_index = body.index('<span class="title">') + len('<span class="title">')
    return body[init_index:body.index('</span>')]


# Get vulnerable products from HTML body
def get_vulnerable_products(body):
    init_index = body.index('<span class="label">Vulnerable:</span>') + len('<span class="label">Vulnerable:</span>')
    tmp_body = body[init_index:]
    init_index = tmp_body.index('<td>') + len('<td>')
    tmp_body = tmp_body[init_index:]
    tmp_body = tmp_body[:tmp_body.index('</td>')]
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
def prepare_output(title, bugtraq_id, vuln_products):
    data = {}
    data['title'] = title
    data['bugtraq_id'] = bugtraq_id
    data['vuln_products'] = vuln_products
    return data


# Requests the bid, parses the HTML and prints the BugTraq info
def get_bid(bugtraq_id):
    r = requests.get("http://www.securityfocus.com/bid/" + str(bugtraq_id))
    if r.status_code == 200:
        try:
            body = r.content.decode("utf-8")
            body = body[body.index('<div id="vulnerability">'):body.index('<span class="label">Not Vulnerable:</span>')]
            title = get_title(body)
            vuln_products = get_vulnerable_products(body)
        except:
            vuln_products = []
        if len(vuln_products) > 0:
            return json.dumps(prepare_output(title, bugtraq_id, vuln_products), sort_keys=True)


# Executes the main function called get_bid in a parallel way
def bid_downloader(first_bid, last_bid):
    output_list = Parallel(n_jobs=100)(delayed(get_bid)(i) for i in range(first_bid, last_bid + 1))
    return [x for x in output_list if x is not None]
