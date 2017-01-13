import logging


# Dagda logger class

class DagdaLogger(logging.Logger):

    # -- Init
    logging.basicConfig(format='<%(asctime)s> <%(levelname)s> <DagdaServer> <%(module)s:%(lineno)d> <%(message)s>')
    _logger = logging.getLogger('DagdaLogger')

    # -- Static methods

    @staticmethod
    def get_logger():
        return DagdaLogger._logger
