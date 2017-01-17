import argparse
import sys


class HistoryCLIParser:

    # -- Public methods

    # HistoryCLIParser Constructor
    def __init__(self):
        super(HistoryCLIParser, self).__init__()
        self.parser = DagdaHistoryParser(prog='dagda.py history', usage=history_parser_text)
        self.parser.add_argument('docker_image_name', metavar='IMAGE_NAME', type=str, nargs='?')
        self.parser.add_argument('--id', type=str)
        self.args, self.unknown = self.parser.parse_known_args(sys.argv[2:])

    # -- Getters

    # Gets docker image name
    def get_docker_image_name(self):
        return self.args.docker_image_name

    # Gets report id
    def get_report_id(self):
        return self.args.id


# Custom parser

class DagdaHistoryParser(argparse.ArgumentParser):

    # Overrides the error method
    def error(self, message):
        self.print_usage()
        exit(2)

    # Overrides the format help method
    def format_help(self):
        return history_parser_text


# Custom text

history_parser_text = '''usage: dagda.py history [-h] [IMAGE_NAME] [--id REPORT_ID]

Your personal docker security analyzer history.

Positional Arguments:
  IMAGE_NAME            the full analysis history for the requested docker image name
                        will be shown ordered by descending date. If the image name is
                        not present, a full analysis history resume will be shown

Optional Arguments:
  -h, --help            show this help message and exit
  --id REPORT_ID        the report with this id will be shown
'''