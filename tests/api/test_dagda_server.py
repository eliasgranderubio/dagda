import unittest
import os
import requests
import time
from unittest.mock import Mock
from api.dagda_server import DagdaServer


# -- Test suite

class DagdaServerTestCase(unittest.TestCase):

    def test_DagdaServer(self):
        ds = DagdaServerWithoutSysdigFalcoMonitor('127.0.0.1', 55555)
        new_pid = os.fork()
        if new_pid == 0:
            ds.run()
        else:
            time.sleep(2)
            response = requests.get('http://127.0.0.1:55555/')
            self.assertEqual(response.status_code, 404)
            os.kill(new_pid, 9)


# -- Mock classes

class DagdaServerWithoutSysdigFalcoMonitor(DagdaServer):
    def __init__(self, dagda_server_host='127.0.0.1', dagda_server_port=5000, mongodb_host='127.0.0.1',
                 mongodb_port=27017):
        super(DagdaServer, self).__init__()
        self.dagda_server_host = dagda_server_host
        self.dagda_server_port = dagda_server_port
        self.sysdig_falco_monitor = Mock()
        self.sysdig_falco_monitor.pre_check.return_value = 0
        self.sysdig_falco_monitor.run.return_value = 0


if __name__ == '__main__':
    unittest.main()
