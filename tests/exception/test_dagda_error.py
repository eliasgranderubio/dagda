import unittest
from dagda.exception.dagda_error import DagdaError


# -- Test suite

class DagdaErrorCase(unittest.TestCase):

    def test_dagda_error(self):
        msg = "Error message"
        try:
            raise DagdaError(msg)
        except DagdaError as e:
            self.assertEqual(e.get_message(), msg)

if __name__ == '__main__':
    unittest.main()
