import unittest
from dagda.api.service.check import check_docker_by_container_id
from dagda.api.service.check import check_docker_by_image_name

# -- Test suite

class CheckApiTestCase(unittest.TestCase):

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


if __name__ == '__main__':
    unittest.main()
