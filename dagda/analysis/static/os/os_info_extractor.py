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
import docker
from exception.dagda_error import DagdaError
from log.dagda_logger import DagdaLogger


# Gets installed software on the OS from docker image
def get_soft_from_docker_image(docker_driver, image_name):
    # Start container
    try:
        # Try to start the docker container with the next entrypoint: 'sleep 30'
        container_id = docker_driver.create_container(image_name, entrypoint='sleep 30')
        docker_driver.docker_start(container_id)
    except docker.errors.ImageNotFound:
        raise DagdaError('No such image: ' + image_name + ':latest')
    except docker.errors.NotFound:
        docker_driver.docker_remove_container(container_id)
        # 'sleep' is not in the $PATH, so try to start the docker container with its default entrypoint
        try:
            container_id = docker_driver.create_container(image_name)
            docker_driver.docker_start(container_id)
        except:
            docker_driver.docker_remove_container(container_id)
            raise DagdaError('The docker container with the <' + image_name + '> image name can not be started.')

    # Get all installed packages
    try:
        products = get_soft_from_docker_container_id(docker_driver, container_id)
    except DagdaError:
        # Stop container
        docker_driver.docker_stop(container_id)
        # Clean up
        docker_driver.docker_remove_container(container_id)
        # Re-raise exception
        raise

    # Stop container
    docker_driver.docker_stop(container_id)
    # Clean up
    docker_driver.docker_remove_container(container_id)
    # Return packages
    return products


# Gets installed software on the OS from docker container id
def get_soft_from_docker_container_id(docker_driver, container_id):
    # Extract Linux image distribution
    response = get_os_name(docker_driver.docker_exec(container_id, 'cat /etc/os-release', True, False))
    if response is None:
        DagdaLogger.get_logger().info('Linux image distribution has not the "/etc/os-release" file. Starting the task '
                                      'for linux distribution identification in a blind mode ...')
        products = get_os_software_packages_blind_mode(docker_driver, container_id)
    else:
        # Get all installed packages
        if 'Red Hat' in response or 'CentOS' in response or 'Fedora' in response or 'openSUSE' in response:
            # Red Hat/CentOS/Fedora/openSUSE
            products = get_os_software_packages(docker_driver, container_id, 'rpm -aqi', parse_rpm_output_list)
        elif 'Debian' in response or 'Ubuntu' in response:
            # Debian/Ubuntu
            products = get_os_software_packages(docker_driver, container_id, 'dpkg -l', parse_dpkg_output_list)
        elif 'Alpine' in response:
            # Alpine
            products = get_os_software_packages(docker_driver, container_id, 'apk -v info', parse_apk_output_list)
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


# Get OS software packages
def get_os_software_packages(docker_driver, container_id, cmd, parser_function):
    packages_info = docker_driver.docker_exec(container_id, cmd, True, False)
    return parser_function(packages_info)


# Get OS software packages in a blind mode
def get_os_software_packages_blind_mode(docker_driver, container_id):
    supported_distributions = [{'cmd': 'rpm -aqi', 'parser': parse_rpm_output_list},
                               {'cmd': 'dpkg -l', 'parser': parse_dpkg_output_list},
                               {'cmd': 'apk -v info', 'parser': parse_apk_output_list}]
    for supported_distribution in supported_distributions:
        packages_info = docker_driver.docker_exec(container_id, supported_distribution['cmd'], True, False)
        if packages_info is not None and 'exec failed' not in packages_info:
            return supported_distribution['parser'](packages_info)

    # The linux image has not a supported distribution or the image has not a package manager
    DagdaLogger.get_logger().warn('Linux image distribution not found. The OS packages report is empty.')
    # Return empty list
    return []


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
