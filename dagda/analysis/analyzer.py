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

import datetime
import requests
import json
from analysis.static.os import os_info_extractor
from analysis.static.dependencies import dep_info_extractor
from analysis.static.av import malware_extractor
from api.internal.internal_server import InternalServer
from log.dagda_logger import DagdaLogger
from analysis.static.util.utils import extract_filesystem_bundle
from analysis.static.util.utils import clean_up


# Analyzer class

class Analyzer:

    # -- Public methods

    # Analyzer Constructor
    def __init__(self, dagda_server_url=None):
        super(Analyzer, self).__init__()
        self.is_remote = False
        if dagda_server_url is not None:
            self.dagda_server_url = dagda_server_url
            self.is_remote = True
        else:
            self.mongoDbDriver = InternalServer.get_mongodb_driver()
        self.dockerDriver = InternalServer.get_docker_driver()

    # Evaluate image from image name or container id
    def evaluate_image(self, image_name, container_id):
        # Init
        data = {}

        # -- Static analysis
        image_name = self.dockerDriver.get_docker_image_name_by_container_id(container_id) if container_id \
                                                                                           else image_name
        os_packages = []
        malware_binaries = []
        dependencies = None
        temp_dir = None
        try:
            # Get OS packages
            if container_id is None:  # Scans the docker image
                os_packages = os_info_extractor.get_soft_from_docker_image(docker_driver=self.dockerDriver,
                                                                           image_name=image_name)
                temp_dir = extract_filesystem_bundle(docker_driver=self.dockerDriver,
                                                     image_name=image_name)
            else:  # Scans the docker container
                os_packages = os_info_extractor.get_soft_from_docker_container_id(docker_driver=self.dockerDriver,
                                                                                  container_id=container_id)
                temp_dir = extract_filesystem_bundle(docker_driver=self.dockerDriver,
                                                     container_id=container_id)

            # Get malware binaries
            malware_binaries = malware_extractor.get_malware_included_in_docker_image(docker_driver=self.dockerDriver,
                                                                                      temp_dir=temp_dir)

            # Get programming language dependencies
            dependencies = dep_info_extractor.get_dependencies_from_docker_image(docker_driver=self.dockerDriver,
                                                                                 image_name=image_name,
                                                                                 temp_dir=temp_dir)
        except Exception as ex:
            message = "Unexpected exception of type {0} occured: {1!r}"\
                .format(type(ex).__name__,  ex.get_message() if type(ex).__name__ == 'DagdaError' else ex.args)
            DagdaLogger.get_logger().error(message)
            data['status'] = message

        # -- Cleanup
        if temp_dir is not None:
            clean_up(temporary_dir=temp_dir)

        # -- Prepare output
        if dependencies is not None:
            data['status'] = 'Completed'
        else:
            dependencies = []

        data['image_name'] = image_name
        data['timestamp'] = datetime.datetime.now().timestamp()
        data['static_analysis'] = self.generate_static_analysis(image_name, os_packages, dependencies, malware_binaries)

        # -- Return
        return data

    # Generates the result of the static analysis
    def generate_static_analysis(self, image_name, os_packages, dependencies, malware_binaries):
        data = {}
        data['os_packages'] = self.generate_os_report(image_name, os_packages)
        data['prog_lang_dependencies'] = self.generate_dependencies_report(image_name, dependencies)
        data['malware_binaries'] = malware_binaries
        return data

    # Generates dependencies report
    def generate_dependencies_report(self, image_name, dependencies):
        data = {}
        dep_details = {}
        dep_details['java'] = []
        dep_details['python'] = []
        dep_details['nodejs'] = []
        dep_details['js'] = []
        dep_details['ruby'] = []
        dep_details['php'] = []
        fp_count = 0
        for dependency in dependencies:
            d = {}
            splitted_dep = dependency.split("#")
            d['product'] = splitted_dep[1]
            d['version'] = splitted_dep[2]
            d['product_file_path'] = splitted_dep[3]
            d['vulnerabilities'] = self.get_vulnerabilities(d['product'], d['version'])
            d['is_vulnerable'] = True
            d['is_false_positive'] = self.is_fp(image_name, d['product'], d['version'])
            if d['is_false_positive']:
                fp_count += 1
            dep_details[splitted_dep[0]].append(d)
        # Prepare output
        data['vuln_dependencies'] = len(dep_details['java']) + len(dep_details['python']) + \
                                    len(dep_details['nodejs']) + len(dep_details['js']) + \
                                    len(dep_details['ruby']) + len(dep_details['php']) - fp_count
        data['dependencies_details'] = dep_details
        # Return
        return data

    # Generates os report
    def generate_os_report(self, image_name, os_packages):
        data = {}
        products_status = []
        vuln_products = 0
        fp_count = 0
        for package in os_packages:
            p = {}
            p['product'] = package['product']
            p['version'] = package['version']
            p['vulnerabilities'] = self.get_vulnerabilities(package['product'], package['version'])
            if len(p['vulnerabilities']) > 0:
                p['is_vulnerable'] = True
                vuln_products += 1
            else:
                p['is_vulnerable'] = False
            p['is_false_positive'] = self.is_fp(image_name, package['product'], package['version'])
            if p['is_false_positive']:
                fp_count += 1
            products_status.append(p)
        # Prepare output
        vuln_products -= fp_count
        data['total_os_packages'] = len(products_status)
        data['vuln_os_packages'] = vuln_products
        data['ok_os_packages'] = data['total_os_packages'] - vuln_products
        data['os_packages_details'] = products_status
        # Return
        return data

    # Gets vulnerabilities by product and version
    def get_vulnerabilities(self, product, version):
        if not self.is_remote:
            return self.mongoDbDriver.get_vulnerabilities(product, version)
        else:
            if product is not None:
                product += '/' + version
            r = requests.get(self.dagda_server_url + '/vuln/products/' + product)
            if r.status_code == 200:
                return json.loads(r.content.decode('utf-8'))
            return []

    # Check if it is a false positive
    def is_fp(self, image_name, product, version):
        if not self.is_remote:
            return self.mongoDbDriver.is_fp(image_name, product, version)
        else:
            if product is not None:
                product += '/' + version
            r = requests.get(self.dagda_server_url + '/history/' + image_name + '/fp/' + product)
            return r.status_code == 204
