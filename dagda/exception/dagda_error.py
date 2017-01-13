# DagdaError class
class DagdaError(Exception):

    # -- Public methods

    # DagdaError Constructor
    def __init__(self, msg):
        super(DagdaError, self).__init__()
        self.message = msg

    # -- Getters

    def get_message(self):
        return self.message
