import argparse
import sys


class CheckCLIParser:
    # -- Public methods

    # CheckDockerCLIParser Constructor
    def __init__(self):
        super(CheckCLIParser, self).__init__()
        self.parser = DagdaCheckParser(prog='dagda.py check', usage=check_parser_text)
        self.parser.add_argument('-i', '--docker_image', type=str)
        self.parser.add_argument('-c', '--container_id', type=str)
        self.args, self.unknown = self.parser.parse_known_args()
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
            print(prog + ': error: arguments --docker_image/--container_id: Both arguments can not be together.',
                  file=sys.stderr)
            return 2
        # Else
        return 0


# Custom parser

class DagdaCheckParser(argparse.ArgumentParser):

    # Overrides the error method
    def error(self, message):
        self.print_usage()
        exit(2)

    # Overrides the format help method
    def format_help(self):
        return check_parser_text


# Custom text

check_parser_text = '''usage: dagda.py check [-h] [-i DOCKER_IMAGE] [-c CONTAINER_ID]

Your personal docker security analyzer.

Optional Arguments:
  -h, --help            show this help message and exit
  -i DOCKER_IMAGE, --docker_image DOCKER_IMAGE
                        the input docker image name
  -c CONTAINER_ID, --container_id CONTAINER_ID
                        the input docker container id
'''