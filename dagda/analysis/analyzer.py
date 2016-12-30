import datetime
from analysis.static.os import os_info_extractor
from analysis.static.dependencies import dep_info_extractor
from api.internal.internal_server import InternalServer


class Analyzer:

    # -- Public methods

    # Analyzer Constructor
    def __init__(self):
        super(Analyzer, self).__init__()
        self.mongoDbDriver = InternalServer.get_mongodb_driver()
        self.dockerDriver = InternalServer.get_docker_driver()

    # Evaluate image from image name or container id
    def evaluate_image(self, image_name, container_id):
        # -- Static analysis
        # Get OS packages
        if image_name:  # Scans the docker image
            os_packages = os_info_extractor.get_soft_from_docker_image(self.dockerDriver, image_name)
        else:  # Scans the docker container
            os_packages = os_info_extractor.get_soft_from_docker_container_id(self.dockerDriver, container_id)
            image_name = self.dockerDriver.get_docker_image_name_from_container_id(container_id)
        # Get programming language dependencies
        dependencies = dep_info_extractor.get_dependencies_from_docker_image(self.dockerDriver, image_name)

        # -- Prepare output
        data = {}
        data['image_name'] = image_name
        data['timestamp'] = datetime.datetime.now().timestamp()
        data['status'] = 'Completed'
        data['static_analysis'] = self.generate_static_analysis(os_packages, dependencies)

        # -- Return
        return data

    # Generates the result of the static analysis
    def generate_static_analysis(self, os_packages, dependencies):
        data = {}
        data['os_packages'] = self.generate_os_report(os_packages)
        data['prog_lang_dependencies'] = self.generate_dependencies_report(dependencies)
        return data

    # Generates dependencies report
    def generate_dependencies_report(self, dependencies):
        data = {}
        dep_details = {}
        dep_details['java'] = []
        dep_details['python'] = []
        dep_details['nodejs'] = []
        dep_details['js'] = []
        dep_details['ruby'] = []
        dep_details['php'] = []
        for dependency in dependencies:
            d = {}
            splitted_dep = dependency.split("#")
            d['product'] = splitted_dep[1]
            d['version'] = splitted_dep[2]
            d['vulnerabilities'] = self.get_vulnerabilities(d['product'], d['version'])
            dep_details[splitted_dep[0]].append(d)
        # Prepare output
        data['vuln_dependencies'] = len(dep_details['java']) + len(dep_details['python']) + \
                                    len(dep_details['nodejs']) + len(dep_details['js']) + \
                                    len(dep_details['ruby']) + len(dep_details['php'])
        data['dependencies_details'] = dep_details
        # Return
        return data

    # Generates os report
    def generate_os_report(self, os_packages):
        data = {}
        products_status = []
        vuln_products = 0
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
            products_status.append(p)
        # Prepare output
        data['total_os_packages'] = len(products_status)
        data['vuln_os_packages'] = vuln_products
        data['ok_os_packages'] = data['total_os_packages'] - vuln_products
        data['os_packages_details'] = products_status
        # Return
        return data

    # Gets vulnerabilities by product and version
    def get_vulnerabilities(self, product, version):
        return self.mongoDbDriver.get_vulnerabilities(product, version)
