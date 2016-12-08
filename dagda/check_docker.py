import datetime
import json
import progressbar
from analysis.static.os import docker_content_parser
from driver.docker_driver import DockerDriver
from driver.mongodb_driver import MongoDbDriver
from cli.check_docker_cli_parser import CheckDockerCLIParser


# Evaluates all products installed in the docker image
def evaluate_products(image_name, products):
    data = {}
    data['image_name'] = image_name
    data['timestamp'] = datetime.datetime.now().timestamp()
    products_status = []
    vuln_products = 0
    bar = progressbar.ProgressBar(redirect_stdout=True)
    for product in bar(products):
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
    # Clean stdout
    clean_progress_bar_from_stdout()
    # Return
    return data


# Gets vulnerabilities by product and version
def get_vulnerabilities(product, version):
    m = MongoDbDriver()
    return m.get_vulnerabilities(product, version)


# Cleans the progress bar from stdout
def clean_progress_bar_from_stdout():
    cursor_up_one = '\x1b[1A'
    erase_line = '\x1b[2K'
    print(cursor_up_one + erase_line, end="")


# Main function
def main(parsed_args):
    m = MongoDbDriver()
    docker_driver = DockerDriver()
    # Scans the docker image/container
    if parsed_args.get_docker_image_name():   # Scan the docker image
        products = docker_content_parser.get_soft_from_docker_image(docker_driver, parsed_args.get_docker_image_name())
        image_name = parsed_args.get_docker_image_name()
    else:   # Scan the docker container
        products = docker_content_parser.get_soft_from_docker_container_id(docker_driver, parsed_args.get_container_id())
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
