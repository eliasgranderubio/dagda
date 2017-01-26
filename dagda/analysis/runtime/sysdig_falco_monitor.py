import io
import os
import time
import json
import platform
import subprocess
import datetime
from shutil import copyfile
from exception.dagda_error import DagdaError
from log.dagda_logger import DagdaLogger


# Sysdig Falco monitor class

class SysdigFalcoMonitor:

    # -- Private attributes

    _falco_output_filename = '/tmp/falco_output.json'
    _falco_custom_rules_filename = '/tmp/custom_falco_rules.yaml'

    # -- Public methods

    # SysdigFalcoMonitor Constructor
    def __init__(self, docker_driver, mongodb_driver, falco_rules_filename):
        super(SysdigFalcoMonitor, self).__init__()
        self.mongodb_driver = mongodb_driver
        self.docker_driver = docker_driver
        self.running_container_id = ''
        if falco_rules_filename is None:
            self.falco_rules = ''
        else:
            copyfile(falco_rules_filename, SysdigFalcoMonitor._falco_custom_rules_filename)
            self.falco_rules = ' -o rules_file=/host' + SysdigFalcoMonitor._falco_custom_rules_filename

    # Pre check for Sysdig falco container
    def pre_check(self):
        # Init
        linux_distro = platform.linux_distribution()[0]
        uname_r = os.uname().release

        # Check requirements
        if not os.path.isfile('/.dockerenv'):  # I'm living in real world!
            if 'Red Hat' == linux_distro or 'CentOS' == linux_distro or 'Fedora' == linux_distro \
                    or 'openSUSE' == linux_distro:
                # Red Hat/CentOS/Fedora/openSUSE
                return_code = subprocess.call(["rpm", "-q", "kernel-devel-" + uname_r],
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif 'Debian' == linux_distro or 'Ubuntu' == linux_distro:
                # Debian/Ubuntu
                return_code = subprocess.call(["dpkg", "-l", "linux-headers-" + uname_r],
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                raise DagdaError('Linux distribution not supported yet.')

            if return_code != 0:
                raise DagdaError('The kernel headers are not installed in the host operating system.')
        else:  # I'm running inside a docker container
            DagdaLogger.get_logger().warning("I'm running inside a docker container, so I can't check if the kernel "
                                             "headers are installed in the host operating system. Please, review it!!")

        # Docker pull for ensuring the sysdig/falco image
        self.docker_driver.docker_pull('sysdig/falco')

        # Stops sysdig/falco containers if there are any
        container_ids = self.docker_driver.get_docker_container_ids_by_image_name('sysdig/falco')
        if len(container_ids) > 0:
            for container_id in container_ids:
                self.docker_driver.docker_stop(container_id)

        # Cleans mongodb falco_events collection
        self.mongodb_driver.delete_falco_events_collection()

        # Starts sysdig running container without custom entrypoint for avoiding:
        # --> Runtime error: error opening device /host/dev/sysdig0
        self.running_container_id = self._start_container()
        time.sleep(30)
        logs = self.docker_driver.docker_logs(self.running_container_id, True, True, False)
        if "Runtime error: error opening device /host/dev/sysdig0" not in logs:
            self.docker_driver.docker_stop(self.running_container_id)
        else:
            raise DagdaError('Runtime error opening device /host/dev/sysdig0.')

    # Runs SysdigFalcoMonitor
    def run(self):
        self.running_container_id = self._start_container('falco -pc -o json_output=true -o file_output.enabled=true ' +
                                                          '-o file_output.filename=/host' +
                                                          SysdigFalcoMonitor._falco_output_filename +
                                                          self.falco_rules)

        # Wait 3 seconds for sysdig/falco start up and creates the output file
        time.sleep(3)

        # Check output file and running docker container
        if not os.path.isfile(SysdigFalcoMonitor._falco_output_filename) or \
           len(self.docker_driver.get_docker_container_ids_by_image_name('sysdig/falco')) == 0:
            raise DagdaError('Sysdig/falco output file not found.')

        # Review sysdig/falco logs after rules parser
        sysdig_falco_logs = self.docker_driver.docker_logs(self.running_container_id, True, True, False)
        if "Rule " in sysdig_falco_logs:
            self._parse_log_and_show_dagda_warnings(sysdig_falco_logs)

        # Read file
        with open(SysdigFalcoMonitor._falco_output_filename, 'rb') as f:
            last_file_position = 0
            fbuf = io.BufferedReader(f)
            while True:
                fbuf.seek(last_file_position)
                content = fbuf.readlines()
                sysdig_falco_events = []
                for line in content:
                    line = line.decode('utf-8').replace("\n", "")
                    json_data = json.loads(line)
                    container_id = json_data['output'].split(" (id=")[1].replace(")", "")
                    if container_id != 'host':
                        try:
                            image_name = self.docker_driver.get_docker_image_name_by_container_id(container_id)
                            json_data['container_id'] = container_id
                            json_data['image_name'] = image_name
                            sysdig_falco_events.append(json_data)
                        except IndexError:
                            # The /tmp/falco_output.json file had information about ancient events, so nothing to do
                            None
                last_file_position = fbuf.tell()
                if len(sysdig_falco_events) > 0:
                    self.mongodb_driver.bulk_insert_sysdig_falco_events(sysdig_falco_events)
                time.sleep(2)

    # Gets running container id
    def get_running_container_id(self):
        return self.running_container_id

    # -- Private methods

    # Starts Sysdig falco container
    def _start_container(self, entrypoint=None):
        # Start container
        container_id = self.docker_driver.create_container('sysdig/falco',
                                                           entrypoint,
                                                           [
                                                              '/host/var/run/docker.sock',
                                                              '/host/dev',
                                                              '/host/proc',
                                                              '/host/boot',
                                                              '/host/lib/modules',
                                                              '/host/usr',
                                                              '/host/tmp'
                                                           ],
                                                           self.docker_driver.get_docker_client().create_host_config(
                                                              binds=[
                                                                  '/var/run/docker.sock:/host/var/run/docker.sock',
                                                                  '/dev:/host/dev',
                                                                  '/proc:/host/proc:ro',
                                                                  '/boot:/host/boot:ro',
                                                                  '/lib/modules:/host/lib/modules:rw',
                                                                  '/usr:/host/usr:ro',
                                                                  '/tmp:/host/tmp:rw'
                                                              ],
                                                              privileged=True))
        self.docker_driver.docker_start(container_id)
        return container_id

    # Parse sysdig/falco logs after rules parser
    def _parse_log_and_show_dagda_warnings(self, sysdig_falco_logs):
        date_prefix = datetime.datetime.now().strftime("%A")[:3] + ' '
        lines = sysdig_falco_logs.split("\n")
        warning = ''
        for line in lines:
            if line.startswith(date_prefix) is not True:
                line = line.strip()
                if line.startswith('Rule '):
                    if warning:
                        DagdaLogger.get_logger().warning(warning.strip())
                    warning = ''
                warning+=' ' + line
