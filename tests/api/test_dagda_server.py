import unittest
import os
import requests
import time
from api.dagda_server import DagdaServer


# -- Test suite

class DagdaServerTestCase(unittest.TestCase):

    def test_DagdaServer(self):
        ds = DagdaServer('127.0.0.1', 55555)
        new_pid = os.fork()
        if new_pid == 0:
            ds.run()
        else:
            time.sleep(2)
            response = requests.get('http://127.0.0.1:55555/')
            self.assertEqual(response.status_code, 404)
            os.kill(new_pid, 9)


if __name__ == '__main__':
    unittest.main()
