import configparser


class ConfigParser:

    # -- Public methods

    # ConfigParser Constructor
    def __init__(self):
        super(ConfigParser, self).__init__()
        self.config = configparser.ConfigParser()
        self.config.read('etc/checker.conf')

    # -- Getters

    # Get Mongodb host
    def get_mongodb_host(self):
        return self.config['MongoDB']['Host']

    # Get Mongodb port
    def get_mongodb_port(self):
        return self.config['MongoDB']['Port']
