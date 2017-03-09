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

import re
import sys
from exception.dagda_error import DagdaError


# Gets installed software on the OS from docker image
def get_soft_from_docker_image(docker_driver, image_name):
    # Start container
    container_id = docker_driver.create_container(image_name, entrypoint='sleep 30')
    docker_driver.docker_start(container_id)
    # Get all installed packages
    products = get_soft_from_docker_container_id(docker_driver, container_id)
    # Stop container
    docker_driver.docker_stop(container_id)
    # Return packages
    return products


# Gets installed software on the OS from docker container id
def get_soft_from_docker_container_id(docker_driver, container_id):
    # Extract Linux image distribution
    response = get_os_name(docker_driver.docker_exec(container_id, 'cat /etc/os-release', True, False))
    # Get all installed packages
    if 'Red Hat' in response or 'CentOS' in response or 'Fedora' in response or 'openSUSE' in response:
        # Red Hat/CentOS/Fedora/openSUSE
        packages_info = docker_driver.docker_exec(container_id, 'rpm -aqi', True, False)
        products = parse_rpm_output_list(packages_info)
    elif 'Debian' in response or 'Ubuntu' in response:
        # Debian/Ubuntu
        packages_info = docker_driver.docker_exec(container_id, 'dpkg -l', True, False)
        products = parse_dpkg_output_list(packages_info)
    elif 'Alpine' in response:
        # Alpine
        packages_info = docker_driver.docker_exec(container_id, 'apk -v info', True, False)
        products = parse_apk_output_list(packages_info)
    else:
        raise DagdaError('Linux image distribution not supported yet.')
    # Return packages
    return products


# Gets OS name from /etc/os-release file
def get_os_name(os_release):
    lines = os_release.split('\n')
    for line in lines:
        if line.startswith('NAME='):
            return line


# Parses the rpm output returned by docker container (Red Hat/CentOS/Fedora/openSUSE)
def parse_rpm_output_list(packages_info):
    package_lines = packages_info.split('\n')
    counter = 0
    products = []
    for line in package_lines:
        if line.startswith("Name        :") or line.startswith("Version     :"):
            info = line.split(':')[1].rstrip().lstrip()
            if counter == 0:
                product = info
                counter += 1
            else:
                version = info
                counter = 0
                data = {}
                data['product'] = product
                data['version'] = version
                products.append(data)
    return products


# Parses the dpkg output returned by docker container (Debian/Ubuntu)
def parse_dpkg_output_list(packages_info):
    package_lines = packages_info.split('\n')
    products = []
    for line in package_lines:
        data = {}
        if line.startswith("ii"):
            splitted_line = re.split('\s+', line)
            # Get product name
            if ':' in splitted_line[1]:
                pos = splitted_line[1].index(':')
                product = splitted_line[1][0:pos]
            else:
                product = splitted_line[1]
            data['product'] = product
            # Get version
            version = splitted_line[2]
            if '-' in version:
                pos = version.index('-')
                version = splitted_line[2][0:pos]
            if ':' in version:
                pos = version.index(':')
                version = version[pos+1:]
            data['version'] = version
            products.append(data)
    return products


# Parses the apk info output returned by docker container (Alpine)
def parse_apk_output_list(packages_info):
    package_lines = packages_info.split('\n')
    products = []
    for line in package_lines:
        data = {}
        if re.search("(.*)-([0-9].*)", line):
            splitted_line = re.match("(.*)-([0-9].*)", line)
            # Get product name
            data['product'] = splitted_line.group(1)
            # Get version
            version = splitted_line.group(2)
            if '-' in version:
                pos = version.index('-')
                version = version[0:pos]
            data['version'] = version
            products.append(data)
    return products
