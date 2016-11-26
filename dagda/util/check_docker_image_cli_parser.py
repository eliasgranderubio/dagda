import argparse
import sys


class CheckDockerImageCLIParser:

    # -- Public methods

    # CheckDockerImageCLIParser Constructor
    def __init__(self):
        super(CheckDockerImageCLIParser, self).__init__()
        self.parser = argparse.ArgumentParser(prog='check_docker_image.py', description='Your personal docker image '
                                                                                        'security analyzer.')
        self.parser.add_argument('-i', '--docker_image', help='the input docker image name')
        self.parser.add_argument('-c', '--container_id', help='the input docker container id')
        self.parser.add_argument('--show_history', action='store_true',
                                 help='the analysis history for the requested docker image will be shown '
                                      'ordered by descending date')
        self.parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.2.0',
                                 help='show the version message and exit')
        self.args = self.parser.parse_args()
        # Verify command line arguments
        status = self.verify_args(self.parser.prog, self.args)
        if status != 0:
            exit(status)

    # -- Getters

    # Gets if only the history should be shown
    def is_history_requested(self):
        return self.args.show_history

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
        elif args.show_history:
            if args.container_id:
                print(prog + ': error: argument --show_history: This argument only works with docker image names.',
                      file=sys.stderr)
                return 2
            elif not args.docker_image:
                print(prog + ': error: argument --show_history: The docker image name is mandatory.', file=sys.stderr)
                return 3
        # Else
        return 0
