import re


# Gets OS name from /etc/os-release file
def get_os_name(os_release):
    lines = os_release.split('\n')
    for line in lines:
        if line.startswith('NAME='):
            return line


# Parses the rpm output returned by docker container (Red Hat/CentOS/Fedora)
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
