import multiprocessing
from driver.mongodb_driver import MongoDbDriver
from driver.docker_driver import DockerDriver


# Internal Dagda server class

class InternalServer:

    # -- Global attributes

    _dagda_edn = multiprocessing.Queue()
    _mongodb_driver = MongoDbDriver()
    _docker_driver = DockerDriver()

    # -- Static methods

    # Gets Dagda EDN
    @staticmethod
    def get_dagda_edn():
        return InternalServer._dagda_edn

    # Gets MongoDB Driver
    @staticmethod
    def get_mongodb_driver():
        return InternalServer._mongodb_driver

    # Sets MongoDB Driver
    @staticmethod
    def set_mongodb_driver(mongodb_host, mongodb_port):
        if not mongodb_host:
            mongodb_host = '127.0.0.1'
        if not mongodb_port:
            mongodb_port = 27017
        InternalServer._mongodb_driver = MongoDbDriver(mongodb_host, mongodb_port)

    # Gets Docker Driver
    @staticmethod
    def get_docker_driver():
        return InternalServer._docker_driver
