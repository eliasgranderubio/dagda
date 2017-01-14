import unittest
from unittest.mock import patch
from dagda.api.service.check import check_docker_by_container_id
from dagda.api.service.check import check_docker_by_image_name


# -- Test suite

class CheckApiTestCase(unittest.TestCase):

    # -- Mock internal classes

    class MockDockerDriver():
        def get_docker_image_name_by_container_id(self, id):
            return 'redis'

        def is_docker_image(self, image_name):
            return True

    class MockDockerDriverPull():
        def get_docker_image_name_by_container_id(self, id):
            return 'redis'

        def docker_pull(self, image_name):
            return ''

        def is_docker_image(self, image_name):
            return False

    class MockMongoDriver():
        def insert_docker_image_scan_result_to_history(self, data):
            return 1

    class MockDagdaEdn():
        def put(self, msg):
            return

    # -- Tests

    def test_check_docker_by_image_name_400(self):
        response, code = check_docker_by_image_name(None)
        self.assertEqual(code, 400)

    def test_check_docker_by_container_id_400(self):
        response, code = check_docker_by_container_id(None)
        self.assertEqual(code, 400)

    def test_check_docker_by_image_name_404(self):
        response, code = check_docker_by_image_name('fake_id')
        self.assertEqual(code, 404)

    def test_check_docker_by_container_id_404(self):
        response, code = check_docker_by_container_id('fake_id')
        self.assertEqual(code, 404)

    @patch('api.internal.internal_server.InternalServer.get_docker_driver', return_value=MockDockerDriver())
    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriver())
    @patch('api.internal.internal_server.InternalServer.get_dagda_edn', return_value=MockDagdaEdn())
    def test_check_docker_by_image_name_202(self, m1, m2, m3):
        response, code = check_docker_by_image_name('fake_id')
        self.assertEqual(code, 202)

    @patch('api.internal.internal_server.InternalServer.get_docker_driver', return_value=MockDockerDriverPull())
    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriver())
    @patch('api.internal.internal_server.InternalServer.get_dagda_edn', return_value=MockDagdaEdn())
    def test_check_docker_by_image_name_202_and_pull(self, m1, m2, m3):
        response, code = check_docker_by_image_name('fake_id')
        self.assertEqual(code, 202)

    @patch('api.internal.internal_server.InternalServer.get_docker_driver', return_value=MockDockerDriver())
    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriver())
    @patch('api.internal.internal_server.InternalServer.get_dagda_edn', return_value=MockDagdaEdn())
    def test_check_docker_by_container_id_202(self, m1, m2, m3):
        response, code = check_docker_by_container_id('fake_id')
        self.assertEqual(code, 202)


if __name__ == '__main__':
    unittest.main()
