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

import os
import requests
from log.dagda_logger import DagdaLogger


# -- Execute Dagda command
def execute_dagda_cmd(cmd, args):
    # Init
    r = None

    # Executes start sub-command
    if cmd == 'start':
        from api.dagda_server import DagdaServer
        ds = DagdaServer(dagda_server_host=args.get_server_host(),
                         dagda_server_port=args.get_server_port(),
                         mongodb_host=args.get_mongodb_host(),
                         mongodb_port=args.get_mongodb_port(),
                         mongodb_ssl=args.is_mongodb_ssl_enabled(),
                         mongodb_user=args.get_mongodb_user(),
                         mongodb_pass=args.get_mongodb_pass(),
                         falco_rules_filename=args.get_falco_rules_filename(),
                         external_falco_output_filename=args.get_external_falco_output_filename())
        ds.run()

    # Executes agent sub-command
    elif cmd == 'agent':
        from remote.agent import Agent
        agent = Agent(dagda_server_url='http://' + args.get_dagda_server() + '/v1')
        agent.run_static_analysis(image_name=args.get_docker_image_name(),
                                  container_id=args.get_container_id())

    # CLI commands
    else:
        dagda_base_url = _get_dagda_base_url()
        # -- Executes vuln sub-command
        if cmd == 'vuln':
            if args.is_initialization_required():
                # Init db
                r = requests.post(dagda_base_url + '/vuln/init')
            elif args.is_init_status_requested():
                # Retrieves the init status
                r = requests.get(dagda_base_url + '/vuln/init-status')
            else:
                if args.get_cve():
                    # Gets products by CVE
                    r = requests.get(dagda_base_url + '/vuln/cve/' + args.get_cve())
                elif args.get_cve_info():
                    # Gets CVE details
                    r = requests.get(dagda_base_url + '/vuln/cve/' + args.get_cve_info() + '/details')
                elif args.get_bid():
                    # Gets products by BID
                    r = requests.get(dagda_base_url + '/vuln/bid/' + str(args.get_bid()))
                elif args.get_bid_info():
                    # Gets BID details
                    r = requests.get(dagda_base_url + '/vuln/bid/' + str(args.get_bid_info()) + '/details')
                elif args.get_exploit_db_id():
                    # Gets products by Exploit DB Id
                    r = requests.get(dagda_base_url + '/vuln/exploit/' + str(args.get_exploit_db_id()))
                elif args.get_exploit_db_info_id():
                    # Gets Exploit details
                    r = requests.get(dagda_base_url + '/vuln/exploit/' + str(args.get_exploit_db_info_id()) +
                                     '/details')
                elif args.get_rhsa():
                    # Gets products by RHSA
                    r = requests.get(dagda_base_url + '/vuln/rhsa/' + args.get_rhsa())
                elif args.get_rhsa_info():
                    # Gets RHSA details
                    r = requests.get(dagda_base_url + '/vuln/rhsa/' + args.get_rhsa_info() + '/details')
                elif args.get_rhba():
                    # Gets products by RHBA
                    r = requests.get(dagda_base_url + '/vuln/rhba/' + args.get_rhba())
                elif args.get_rhba_info():
                    # Gets RHBA details
                    r = requests.get(dagda_base_url + '/vuln/rhba/' + args.get_rhba_info() + '/details')
                else:
                    # Gets CVEs, BIDs, RHBAs, RHSAs and Exploit_DB Ids by product and version
                    if not args.get_product_version():
                        r = requests.get(dagda_base_url + '/vuln/products/' + args.get_product())
                    else:
                        r = requests.get(dagda_base_url + '/vuln/products/' + args.get_product() + '/' +
                                         args.get_product_version())

        # Executes check sub-command
        elif cmd == 'check':
            if args.get_docker_image_name():
                r = requests.post(dagda_base_url + '/check/images/' + args.get_docker_image_name())
            else:
                r = requests.post(dagda_base_url + '/check/containers/' + args.get_container_id())

        # Executes history sub-command
        elif cmd == 'history':
            # Gets the global history
            if not args.get_docker_image_name():
                r = requests.get(dagda_base_url + '/history')
            else:
                # Updates product vulnerability as false positive
                if args.get_fp() is not None:
                    fp_product, fp_version = args.get_fp()
                    if fp_version is not None:
                        fp_product += '/' + fp_version
                    r = requests.patch(dagda_base_url + '/history/' + args.get_docker_image_name() + '/fp/'
                                       + fp_product)
                # Checks if a product vulnerability is a false positive
                if args.get_is_fp() is not None:
                    fp_product, fp_version = args.get_is_fp()
                    if fp_version is not None:
                        fp_product += '/' + fp_version
                    r = requests.get(dagda_base_url + '/history/' + args.get_docker_image_name() + '/fp/'
                                     + fp_product)
                # Gets the image history
                else:
                    query_params = ''
                    if args.get_report_id() is not None:
                        query_params = '?id=' + args.get_report_id()
                    r = requests.get(dagda_base_url + '/history/' + args.get_docker_image_name() + query_params)

        # Executes monitor sub-command
        elif cmd == 'monitor':
            if args.is_start():
                r = requests.post(dagda_base_url + '/monitor/containers/' + args.get_container_id() + '/start')
            elif args.is_stop():
                r = requests.post(dagda_base_url + '/monitor/containers/' + args.get_container_id() + '/stop')

        # Executes docker sub-command
        elif cmd == 'docker':
            r = requests.get(dagda_base_url + '/docker/' + args.get_command())

    # Return
    return r


# -- Private methods

# -- Get Dagda server base url
def _get_dagda_base_url():
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

