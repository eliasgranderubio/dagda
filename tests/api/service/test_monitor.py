import unittest
from unittest.mock import patch
from dagda.api.service.monitor import start_monitor_by_container_id
from dagda.api.service.monitor import stop_monitor_by_container_id


# -- Test suite

class MonitorApiTestCase(unittest.TestCase):

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


if __name__ == '__main__':
    unittest.main()
