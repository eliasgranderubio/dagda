import argparse
import sys


class DockerHistoryCLIParser:

    # -- Public methods

    # DockerHistoryCLIParser Constructor
    def __init__(self):
        super(DockerHistoryCLIParser, self).__init__()
        self.parser = argparse.ArgumentParser(prog='docker_history.py', description='Your personal docker security '
                                                                                    'analyzer history.')
        self.parser.add_argument('docker_image_name', metavar='IMAGE_NAME', type=str,
                                 help='the analysis history for the requested docker image name will be shown ordered'
                                      ' by descending date')
        self.parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.2.0',
                                 help='show the version message and exit')
        self.args = self.parser.parse_args()
        # Verify command line arguments
        status = self.verify_args(self.parser.prog, self.args)
        if status != 0:
            exit(status)

    # -- Getters

    # Gets docker image name
    def get_docker_image_name(self):
        return self.args.docker_image_name

    # -- Static methods

    # Verify command line arguments
    @staticmethod
    def verify_args(prog, args):
        if not args.docker_image_name:
            print(prog + ': error: missing arguments.', file=sys.stderr)
            return 1
        # Else
        return 0
