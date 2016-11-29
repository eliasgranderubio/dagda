import datetime
import json
import dockerUtil.docker_content_parser
from dockerUtil.docker_driver import DockerDriver
from vulnDB.mongodb_driver import MongoDbDriver
from util.check_docker_cli_parser import CheckDockerCLIParser
import sys


# Gets installed software from docker image
def get_soft_from_docker_image(docker_driver, image_name):
    # Start container
    container_id = docker_driver.create_container(image_name)
    docker_driver.docker_start(container_id)
    # Get all installed packages
    products = get_soft_from_docker_container_id(docker_driver, container_id)
    # Stop container
    docker_driver.docker_stop(container_id)
    # Return packages
    return products


# Gets installed software from docker container id
def get_soft_from_docker_container_id(docker_driver, container_id):
    # Extract Linux image distribution
    response = dockerUtil.docker_content_parser.get_os_name(
        docker_driver.docker_exec(container_id, 'cat /etc/os-release'))
    # Get all installed packages
    if 'Red Hat' in response or 'CentOS' in response or 'Fedora' in response or 'openSUSE' in response:
        # Red Hat/CentOS/Fedora/openSUSE
        packages_info = docker_driver.docker_exec(container_id, 'rpm -aqi')
        products = dockerUtil.docker_content_parser.parse_rpm_output_list(packages_info)
    elif 'Debian' in response or 'Ubuntu' in response:
        # Debian/Ubuntu
        packages_info = docker_driver.docker_exec(container_id, 'dpkg -l')
        products = dockerUtil.docker_content_parser.parse_dpkg_output_list(packages_info)
    elif 'Alpine' in response:
        # Alpine
        packages_info = docker_driver.docker_exec(container_id, 'apk -v info')
        products = dockerUtil.docker_content_parser.parse_apk_output_list(packages_info)
    else:
        print('Error: Linux image distribution not supported yet.', file=sys.stderr)
        exit(1)
    # Return packages
    return products


# Evaluates all products installed in the docker image
def evaluate_products(image_name, products):
    data = {}
    data['image_name'] = image_name
    data['timestamp'] = datetime.datetime.now().timestamp()
    products_status = []
    vuln_products = 0
    for product in products:
        p = {}
        p['product'] = product['product']
        p['version'] = product['version']
        p['vulnerabilities'] = get_vulnerabilities(product['product'], product['version'])
        if len(p['vulnerabilities']) > 0:
            p['is_vulnerable'] = True
            vuln_products += 1
        else:
            p['is_vulnerable'] = False
        products_status.append(p)
    data['evaluated_packages_info'] = products_status
    data['total_products'] = len(products_status)
    data['vuln_products'] = vuln_products
    data['ok_products'] = data['total_products'] - vuln_products
    return data


# Gets vulnerabilities by product and version
def get_vulnerabilities(product, version):
    m = MongoDbDriver()
    return m.get_vulnerabilities(product, version)


# Main function
def main(parsed_args):
    m = MongoDbDriver()
    docker_driver = DockerDriver()
    # Scans the docker image/container
    if parsed_args.get_docker_image_name():   # Scan the docker image
        products = get_soft_from_docker_image(docker_driver, parsed_args.get_docker_image_name())
        image_name = parsed_args.get_docker_image_name()
    else:   # Scan the docker container
        products = get_soft_from_docker_container_id(docker_driver, parsed_args.get_container_id())
        image_name = docker_driver.get_docker_image_name_from_container_id(parsed_args.get_container_id())
    # Evaluate the installed software
    evaluated_docker_image = evaluate_products(image_name, products)
    # Update the scan history
    m.insert_docker_image_scan_result_to_history(evaluated_docker_image)
    # Prepares output
    evaluated_docker_image['timestamp'] = str(
        datetime.datetime.utcfromtimestamp(evaluated_docker_image['timestamp']))
    del evaluated_docker_image['_id']
    print(json.dumps(evaluated_docker_image, sort_keys=True, indent=4))


if __name__ == "__main__":
    main(CheckDockerCLIParser())
