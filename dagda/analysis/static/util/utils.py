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
import shutil
import tempfile
from tarfile import TarFile


# Prepare filesystem bundle
def extract_filesystem_bundle(docker_driver, container_id=None, image_name=None):
    temporary_dir = tempfile.mkdtemp()
    # Get and save filesystem bundle
    if container_id is not None:
        data = docker_driver.get_docker_client().export(container=container_id).data
        name = container_id
    else:
        data = docker_driver.get_docker_client().get_image(image=image_name).data
        name = image_name.replace('/', '_')
    with open(temporary_dir + "/" + name + ".tar", "wb") as file:
        file.write(data)
    # Untar filesystem bundle
    tarfile = TarFile(temporary_dir + "/" + name + ".tar")
    tarfile.extractall(temporary_dir)
    os.remove(temporary_dir + "/" + name + ".tar")
    # Return
    return temporary_dir


# Clean the temporary directory
def clean_up(temporary_dir):
    shutil.rmtree(temporary_dir)
