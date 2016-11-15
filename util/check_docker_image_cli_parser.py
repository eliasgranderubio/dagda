import argparse
import sys


class CheckDockerImageCLIParser:

    # -- Public methods

    # CheckDockerImageCLIParser Constructor
    def __init__(self):
        super(CheckDockerImageCLIParser, self).__init__()
        self.parser = argparse.ArgumentParser(prog='check_docker_image.py', description='Your personal docker image '
                                                                                        'security scanner.')
        self.parser.add_argument('-i', '--docker_image', help='the input docker image name. This argument is mandatory')
        self.parser.add_argument('--show_history', action='store_true',
                                 help='the security scan history for the requested docker image will be shown '
                                      'order by date from the newest to oldest')
        self.args = self.parser.parse_args()

    # -- Getters

    # Gets if only the history should be shown
    def is_history_requested(self):
        if self.args.show_history:
            return True
        else:
            return False

    # Gets docker image name
    def get_docker_image_name(self):
        if not self.args.docker_image:
            print(self.parser.prog + ': error: argument -i/--docker_image: The docker image name is mandatory.',
                  file=sys.stderr)
            exit(2)
        else:
            return self.args.docker_image
