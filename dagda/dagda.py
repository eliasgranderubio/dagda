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
import os
import requests
from cli.dagda_cli_parser import DagdaCLIParser
from log.dagda_logger import DagdaLogger


# -- Get Dagda server base url
def get_dagda_base_url():
    # -- Load env variables
    try:
        dagda_host = os.environ['DAGDA_HOST']
    except KeyError:
        DagdaLogger.get_logger().error('DAGDA_HOST environment variable is not set.')
        exit(1)

    try:
        dagda_port = os.environ['DAGDA_PORT']
    except KeyError:
        DagdaLogger.get_logger().error('DAGDA_PORT environment variable is not set.')
        exit(1)

    # -- Return Dagda server base url
    return 'http://' + dagda_host + ':' + dagda_port + '/v1'


# -- Main function
def main(parsed_args):
    # -- Init
    cmd = parsed_args.get_command()
    parsed_args = parsed_args.get_extra_args()

    # Executes start sub-command
    if cmd == 'start':
        from api.dagda_server import DagdaServer
        ds = DagdaServer(dagda_server_host=parsed_args.get_server_host(),
                         dagda_server_port=parsed_args.get_server_port(),
                         mongodb_host=parsed_args.get_mongodb_host(),
                         mongodb_port=parsed_args.get_mongodb_port(),
                         mongodb_ssl=parsed_args.is_mongodb_ssl_enabled(),
                         mongodb_user=parsed_args.get_mongodb_user(),
                         mongodb_pass=parsed_args.get_mongodb_pass(),
                         falco_rules_filename=parsed_args.get_falco_rules_filename())
        ds.run()

    else:
        dagda_base_url = get_dagda_base_url()
        # -- Executes vuln sub-command
        if cmd == 'vuln':
            if parsed_args.is_initialization_required():
                # Init db
                r = requests.post(dagda_base_url + '/vuln/init')
            elif parsed_args.is_init_status_requested():
                # Retrieves the init status
                r = requests.get(dagda_base_url + '/vuln/init-status')
            else:
                if parsed_args.get_cve():
                    # Gets products by CVE
                    r = requests.get(dagda_base_url + '/vuln/cve/' + parsed_args.get_cve())
                elif parsed_args.get_cve_info():
                    r = requests.get(dagda_base_url + '/vuln/cve/' + parsed_args.get_cve_info() + '/details')
                elif parsed_args.get_bid():
                    # Gets products by BID
                    r = requests.get(dagda_base_url + '/vuln/bid/' + str(parsed_args.get_bid()))
                elif parsed_args.get_exploit_db_id():
                    # Gets products by Exploit DB Id
                    r = requests.get(dagda_base_url + '/vuln/exploit/' + str(parsed_args.get_exploit_db_id()))
                else:
                    # Gets CVEs, BIDs and Exploit_DB Ids by product and version
                    if not parsed_args.get_product_version():
                        r = requests.get(dagda_base_url + '/vuln/products/' + parsed_args.get_product())
                    else:
                        r = requests.get(dagda_base_url + '/vuln/products/' + parsed_args.get_product() + '/' +
                                         parsed_args.get_product_version())

        # Executes check sub-command
        elif cmd == 'check':
            if parsed_args.get_docker_image_name():
                r = requests.post(dagda_base_url + '/check/images/' + parsed_args.get_docker_image_name())
            else:
                r = requests.post(dagda_base_url + '/check/containers/' + parsed_args.get_container_id())

        # Executes history sub-command
        elif cmd == 'history':
            # Gets the history
            if not parsed_args.get_docker_image_name():
                r = requests.get(dagda_base_url + '/history')
            else:
                query_params = ''
                if parsed_args.get_report_id() is not None:
                    query_params = '?id=' + parsed_args.get_report_id()
                r = requests.get(dagda_base_url + '/history/' + parsed_args.get_docker_image_name() + query_params)

        # Executes monitor sub-command
        elif cmd == 'monitor':
            if parsed_args.is_start():
                r = requests.post(dagda_base_url + '/monitor/containers/' + parsed_args.get_container_id() + '/start')
            elif parsed_args.is_stop():
                r = requests.post(dagda_base_url + '/monitor/containers/' + parsed_args.get_container_id() + '/stop')

        # Executes docker sub-command
        elif cmd == 'docker':
            r = requests.get(dagda_base_url + '/docker/' + parsed_args.get_command())

        # -- Print cmd output
        if r is not None:
            print(json.dumps(json.loads(r.content.decode('utf-8')), sort_keys=True, indent=4))


if __name__ == "__main__":
    main(DagdaCLIParser())
