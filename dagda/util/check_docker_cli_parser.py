import argparse
import sys


class CheckDockerCLIParser:

    # -- Public methods

    # CheckDockerCLIParser Constructor
    def __init__(self):
        super(CheckDockerCLIParser, self).__init__()
        self.parser = argparse.ArgumentParser(prog='check_docker.py', description='Your personal docker security '
                                                                                  'analyzer.')
        self.parser.add_argument('-i', '--docker_image', help='the input docker image name')
        self.parser.add_argument('-c', '--container_id', help='the input docker container id')
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
        return self.args.docker_image

    # Gets docker container id
    def get_container_id(self):
        return self.args.container_id

    # -- Static methods

    # Verify command line arguments
    @staticmethod
    def verify_args(prog, args):
        if not args.container_id and not args.docker_image:
            print(prog + ': error: missing arguments.', file=sys.stderr)
            return 1
        elif args.container_id and args.docker_image:
            print(prog + ': error: arguments ----docker_image/--container_id: Both arguments can not be together.',
                  file=sys.stderr)
            return 2
        # Else
        return 0
