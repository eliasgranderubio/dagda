import argparse
import sys


class DockerCLIParser:

    # -- Public methods

    # DockerCLIParser Constructor
    def __init__(self):
        super(DockerCLIParser, self).__init__()
        self.parser = DagdaDockerParser(prog='dagda.py docker', usage=docker_parser_text)
        self.parser.add_argument('command', choices=['containers', 'images'])
        self.args, self.unknown = self.parser.parse_known_args(sys.argv[2:])

    # -- Getters

    # Gets command
    def get_command(self):
        return self.args.command


# Custom parser

class DagdaDockerParser(argparse.ArgumentParser):

    # Overrides the error method
    def error(self, message):
        self.print_usage()
        exit(2)

    # Overrides the format help method
    def format_help(self):
        return docker_parser_text


# Custom text

docker_parser_text = '''usage: dagda.py docker [-h] <command>

Your personal docker API.


Dagda Commands:
  containers            list all running docker containers
  images                list all docker images


Optional Arguments:
  -h, --help            show this help message and exit
'''