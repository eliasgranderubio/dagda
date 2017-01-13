import unittest
from unittest.mock import patch
from dagda.api.service.monitor import start_monitor_by_container_id
from dagda.api.service.monitor import stop_monitor_by_container_id


# -- Test suite

class MonitorApiTestCase(unittest.TestCase):

    # -- Mock internal classes

    class MockDockerDriver():
        def get_docker_image_name_from_container_id(self, id):
            return 'redis'

    class MockMongoDriverStartTrue():
        def is_there_a_started_monitoring(self, id):
            return True

        def update_runtime_monitoring_analysis(self, id):
            return

        def get_a_started_monitoring(self, id):
            return {'runtime_analysis': {'stop_timestamp': None}, 'status': None, '_id': 1234567890}

        def update_docker_image_scan_result_to_history(self, id, result):
            return

        def get_docker_image_history(self, image_name, id):
            return [{'runtime_analysis': {'stop_timestamp': None}, 'status': None, '_id': 1234567890}]

    class MockMongoDriverStartFalse():
        def is_there_a_started_monitoring(self, id):
            return False

        def insert_docker_image_scan_result_to_history(self, history):
            return 1234567890

    # -- Tests

    @patch('api.internal.internal_server.InternalServer.is_runtime_analysis_enabled', return_value=False)
    def test_start_monitor_by_container_id_503(self,m):
        response, code = start_monitor_by_container_id('test_id')
        self.assertEqual(code, 503)

    @patch('api.internal.internal_server.InternalServer.is_runtime_analysis_enabled', return_value=False)
    def test_stop_monitor_by_container_id_503(self,m):
        response, code = stop_monitor_by_container_id('test_id')
        self.assertEqual(code, 503)

    @patch('api.internal.internal_server.InternalServer.is_runtime_analysis_enabled', return_value=True)
    def test_start_monitor_by_container_id_400(self, m):
        response, code = start_monitor_by_container_id(None)
        self.assertEqual(code, 400)

    @patch('api.internal.internal_server.InternalServer.is_runtime_analysis_enabled', return_value=True)
    def test_stop_monitor_by_container_id_400(self, m):
        response, code = stop_monitor_by_container_id(None)
        self.assertEqual(code, 400)

    @patch('api.internal.internal_server.InternalServer.is_runtime_analysis_enabled', return_value=True)
    def test_start_monitor_by_container_id_404(self, m):
        response, code = start_monitor_by_container_id('fake_id')
        self.assertEqual(code, 404)

    @patch('api.internal.internal_server.InternalServer.is_runtime_analysis_enabled', return_value=True)
    def test_stop_monitor_by_container_id_404(self, m):
        response, code = stop_monitor_by_container_id('fake_id')
        self.assertEqual(code, 404)

    @patch('api.internal.internal_server.InternalServer.is_runtime_analysis_enabled', return_value=True)
    @patch('api.internal.internal_server.InternalServer.get_docker_driver', return_value=MockDockerDriver())
    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverStartTrue())
    def test_start_monitor_by_container_id_400_started(self, m1, m2, m3):
        response, code = start_monitor_by_container_id('id')
        self.assertEqual(code, 400)

    @patch('api.internal.internal_server.InternalServer.is_runtime_analysis_enabled', return_value=True)
    @patch('api.internal.internal_server.InternalServer.get_docker_driver', return_value=MockDockerDriver())
    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverStartFalse())
    def test_stop_monitor_by_container_id_400_not_started(self, m1, m2, m3):
        response, code = stop_monitor_by_container_id('id')
        self.assertEqual(code, 400)

    @patch('api.internal.internal_server.InternalServer.is_runtime_analysis_enabled', return_value=True)
    @patch('api.internal.internal_server.InternalServer.get_docker_driver', return_value=MockDockerDriver())
    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverStartFalse())
    def test_start_monitor_by_container_id_OK(self, m1, m2, m3):
        response, code = start_monitor_by_container_id('id')
        self.assertEqual(code, 202)

    @patch('api.internal.internal_server.InternalServer.is_runtime_analysis_enabled', return_value=True)
    @patch('api.internal.internal_server.InternalServer.get_docker_driver', return_value=MockDockerDriver())
    @patch('api.internal.internal_server.InternalServer.get_mongodb_driver', return_value=MockMongoDriverStartTrue())
    def test_stop_monitor_by_container_id_OK(self, m1, m2, m3):
        response = stop_monitor_by_container_id('id')
        self.assertEqual(response, '{"_id": 1234567890, "runtime_analysis": {"stop_timestamp": null}, "status": null}')


if __name__ == '__main__':
    unittest.main()
