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

import unittest
from unittest.mock import patch
from dagda.api.service.docker import get_all_docker_images
from dagda.api.service.docker import get_all_running_containers
from dagda.api.service.docker import sizeof_fmt


# -- Test suite

class DockerApiTestCase(unittest.TestCase):

    # -- Mock internal classes

    class MockDockerDriverEmpty():

        class MockDockerClient():
            def containers(self):
                return []

            def images(self):
                return []

        def get_docker_client(self):
            return self.MockDockerClient()

    class MockDockerDriver():

        class MockDockerClient():
            def containers(self):
                return [{'Image': 'mongo', 'Mounts': [{'Destination': '/data/configdb', 'Driver': 'local', 'Name': '4a26849615bb3f54ccc2f1833010826550f07bfcda279d76b3c4f3b79c61063c', 'Mode': '', 'Propagation': '', 'Source': '/var/lib/docker/volumes/4a26849615bb3f54ccc2f1833010826550f07bfcda279d76b3c4f3b79c61063c/_data', 'RW': True}, {'Destination': '/data/db', 'Driver': 'local', 'Name': '1fb738b171443c654f163850b1eb873902a9c018e87706512c15e0fc78406005', 'Mode': '', 'Propagation': '', 'Source': '/var/lib/docker/volumes/1fb738b171443c654f163850b1eb873902a9c018e87706512c15e0fc78406005/_data', 'RW': True}], 'Command': '/entrypoint.sh mongod', 'Ports': [{'Type': 'tcp', 'PrivatePort': 27017}], 'NetworkSettings': {'Networks': {'bridge': {'EndpointID': 'fa5b09bf01d1752cc411618c1884e7035c6f8af4138f6a6e5e6f1c883215a398', 'IPPrefixLen': 16, 'IPAMConfig': None, 'GlobalIPv6Address': '', 'IPv6Gateway': '', 'MacAddress': '02:42:ac:11:00:03', 'Aliases': None, 'IPAddress': '172.17.0.3', 'NetworkID': '4b40ec6b168d22e8c619cf07590c13f9a265df4c30f38b240a201c6ccb2524a8', 'Gateway': '172.17.0.1', 'Links': None, 'GlobalIPv6PrefixLen': 0}}}, 'State': 'running', 'ImageID': 'sha256:86e302671af465e21742fb4932322012da8abaff5134a7dd194dc47944461549', 'Names': ['/prickly_ride'], 'HostConfig': {'NetworkMode': 'default'}, 'Id': 'eeec610d87717e43894a66b38fabc93615189a9a22e57240a4f3749289f1ba01', 'Status': 'Up 1 seconds', 'Created': 1484414163, 'Labels': {}}, {'Image': 'jboss/wildfly', 'Mounts': [], 'Command': '/opt/jboss/wildfly/bin/standalone.sh -b 0.0.0.0', 'Ports': [{'Type': 'tcp', 'PrivatePort': 8080}], 'NetworkSettings': {'Networks': {'bridge': {'EndpointID': '38bc01e7286d10891806420b072c40409f27f96767dae694244ffa7d72d47aa2', 'IPPrefixLen': 16, 'IPAMConfig': None, 'GlobalIPv6Address': '', 'IPv6Gateway': '', 'MacAddress': '02:42:ac:11:00:02', 'Aliases': None, 'IPAddress': '172.17.0.2', 'NetworkID': '4b40ec6b168d22e8c619cf07590c13f9a265df4c30f38b240a201c6ccb2524a8', 'Gateway': '172.17.0.1', 'Links': None, 'GlobalIPv6PrefixLen': 0}}}, 'State': 'running', 'ImageID': 'sha256:f916ed31837d0ec79bd239a398c13d40ec93dcaa0dad6bb3ac36ab4953161f0f', 'Names': ['/stupefied_stallman'], 'HostConfig': {'NetworkMode': 'default'}, 'Id': 'ee1a32ddfffd2e3b66c76dc53eef432dfb07b4c90b8224613dcb6be8ab105320', 'Status': 'Up 10 seconds', 'Created': 1484414156, 'Labels': {'license': 'GPLv2', 'build-date': '20161102', 'vendor': 'CentOS', 'name': 'CentOS Base Image'}}]

            def images(self):
                return [{'Labels': {}, 'RepoTags': ['dagda_dagda:latest'], 'Id': 'sha256:f846515186f0734c327efcfa43b484d78220ab8b274d5e54b170a1c6144c6cbd', 'VirtualSize': 100893927, 'Size': 100893927, 'Created': 1483873177, 'ParentId': 'sha256:e5e28ce5c45699575583264ae9be9f35b6af76d13308192e01e3ace65d73b5a7', 'RepoDigests': None}, {'Labels': {}, 'RepoTags': ['python:3.4.5-alpine'], 'Id': 'sha256:0eb0091592b3d8aab929e19041330d307e0e3302cf58ae8753276a2860c45037', 'VirtualSize': 82364493, 'Size': 82364493, 'Created': 1482874759, 'ParentId': '', 'RepoDigests': ['python@sha256:a4bae34fb471e7093e74fc57ea3dc580635d2821d55c4a7ad727e254f34a882a']}, {'Labels': None, 'RepoTags': ['alpine:latest'], 'Id': 'sha256:88e169ea8f46ff0d0df784b1b254a15ecfaf045aee1856dca1ec242fdd231ddd', 'VirtualSize': 3979756, 'Size': 3979756, 'Created': 1482862645, 'ParentId': '', 'RepoDigests': ['alpine@sha256:dfbd4a3a8ebca874ebd2474f044a0b33600d4523d03b0df76e5c5986cb02d7e8']}, {'Labels': {'RUN': 'docker run -i -t -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro --name NAME IMAGE'}, 'RepoTags': ['sysdig/falco:latest'], 'Id': 'sha256:285353e9835de79f7402bb2866f2e8552584a348305c545d7287a81dc2014f0e', 'VirtualSize': 346035227, 'Size': 346035227, 'Created': 1482449119, 'ParentId': '', 'RepoDigests': ['sysdig/falco@sha256:64a19373892d5b0cadccb2cb3925cd343a9ee210db543e44cb74c8b8ac016413']}, {'Labels': {}, 'RepoTags': ['redis:latest'], 'Id': 'sha256:d59dc9e6d0bf135e969796ba00c9f458e3b65c47d8a7349a3d6e0974ec02e103', 'VirtualSize': 182896153, 'Size': 182896153, 'Created': 1481743509, 'ParentId': '', 'RepoDigests': ['redis@sha256:eed4da4937cb562e9005f3c66eb8c3abc14bb95ad497c03dc89d66bcd172fc7f']}, {'Labels': {}, 'RepoTags': ['mongo:latest', 'mongo:latest'], 'Id': 'sha256:86e302671af465e21742fb4932322012da8abaff5134a7dd194dc47944461549', 'VirtualSize': 401895934, 'Size': 401895934, 'Created': 1480543691, 'ParentId': '', 'RepoDigests': ['mongo@sha256:d929ffc5d0871712198be82c475397e5e9c71f3d2a9fa4b304f623ad09ad204b', 'mongo@sha256:d929ffc5d0871712198be82c475397e5e9c71f3d2a9fa4b304f623ad09ad204b']}, {'Labels': {'vendor': 'CentOS', 'build-date': '20161102', 'name': 'CentOS Base Image', 'license': 'GPLv2'}, 'RepoTags': ['jboss/wildfly:latest', 'jboss/wildfly:latest'], 'Id': 'sha256:f916ed31837d0ec79bd239a398c13d40ec93dcaa0dad6bb3ac36ab4953161f0f', 'VirtualSize': 582564927, 'Size': 582564927, 'Created': 1479505764, 'ParentId': '', 'RepoDigests': ['jboss/wildfly@sha256:12dde9a59c2f64387114c5587455eae8b1bd4264f8c1a1679b2d2e656e5502a6', 'jboss/wildfly@sha256:12dde9a59c2f64387114c5587455eae8b1bd4264f8c1a1679b2d2e656e5502a6']}, {'Labels': {}, 'RepoTags': ['deepfenceio/deepfence_depcheck:latest', 'deepfenceio/deepfence_depcheck:latest'], 'Id': 'sha256:c18ba084d113f47a05ed8d40a004443f92525e42c99dce512a88576396fa457e', 'VirtualSize': 884997791, 'Size': 884997791, 'Created': 1476433732, 'ParentId': '', 'RepoDigests': ['deepfenceio/deepfence_depcheck@sha256:7412104b40657cb535091eae71f6e5bca14befbba25de669969276e5365fc4fb', 'deepfenceio/deepfence_depcheck@sha256:7412104b40657cb535091eae71f6e5bca14befbba25de669969276e5365fc4fb']}]

        def get_docker_client(self):
            return self.MockDockerClient()

    # -- Tests

    def test_sizeof_fmt(self):
        response = sizeof_fmt(1099511627776.0)
        self.assertEqual(response, '1.0YB')

    @patch('api.internal.internal_server.InternalServer.get_docker_driver', return_value=MockDockerDriver())
    def test_get_all_docker_images(self, m1):
        response = get_all_docker_images()
        self.assertEqual(response, mock_images_result)

    @patch('api.internal.internal_server.InternalServer.get_docker_driver', return_value=MockDockerDriver())
    def test_get_all_running_containers(self, m1):
        response = get_all_running_containers()
        self.assertEqual(response, mock_containers_result)

# -- Mock Constants

mock_images_result = '[{"created": "2017-01-08 10:59:37", "id": "f846515186f0", "size": "96.2MB", "tags": ["dagda_dagda:latest"]}, {"created": "2016-12-27 21:39:19", "id": "0eb0091592b3", "size": "78.5MB", "tags": ["python:3.4.5-alpine"]}, {"created": "2016-12-27 18:17:25", "id": "88e169ea8f46", "size": "3.8MB", "tags": ["alpine:latest"]}, {"created": "2016-12-22 23:25:19", "id": "285353e9835d", "size": "330.0MB", "tags": ["sysdig/falco:latest"]}, {"created": "2016-12-14 19:25:09", "id": "d59dc9e6d0bf", "size": "174.4MB", "tags": ["redis:latest"]}, {"created": "2016-11-30 22:08:11", "id": "86e302671af4", "size": "383.3MB", "tags": ["mongo:latest"]}, {"created": "2016-11-18 21:49:24", "id": "f916ed31837d", "size": "555.6MB", "tags": ["jboss/wildfly:latest"]}, {"created": "2016-10-14 08:28:52", "id": "c18ba084d113", "size": "844.0MB", "tags": ["deepfenceio/deepfence_depcheck:latest"]}]'

mock_containers_result = '[{"created": "2017-01-14 17:16:03", "id": "eeec610d8771", "image": "mongo", "name": "prickly_ride", "status": "running"}, {"created": "2017-01-14 17:15:56", "id": "ee1a32ddfffd", "image": "jboss/wildfly", "name": "stupefied_stallman", "status": "running"}]'


if __name__ == '__main__':
    unittest.main()
