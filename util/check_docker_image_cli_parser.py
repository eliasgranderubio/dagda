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
        self.parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1.0',
                                 help='show the version message and exit')
        self.args = self.parser.parse_args()
        self.__verify_args()

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

    # -- Private methods

    # Verify command line arguments
    def __verify_args(self):
        if not self.args.container_id and not self.args.docker_image:
            print(self.parser.prog + ': error: missing arguments.', file=sys.stderr)
            exit(1)
        elif self.args.show_history:
            if self.args.container_id:
                print(self.parser.prog + ': error: argument --show_history: This argument only works with docker '
                                         'image names.',
                      file=sys.stderr)
                exit(1)
            elif not self.args.docker_image:
                print(self.parser.prog + ': error: argument --show_history: The docker image name is mandatory.',
                      file=sys.stderr)
                exit(1)
