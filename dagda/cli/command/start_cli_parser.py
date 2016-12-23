import argparse
import sys


class StartCLIParser:

    # -- Public methods

    # StartCLIParser Constructor
    def __init__(self):
        super(StartCLIParser, self).__init__()
        self.parser = DagdaStartParser(prog='dagda.py vuln', usage=start_parser_text)
        self.parser.add_argument('-s', '--server_host', type=str)
        self.parser.add_argument('-p', '--server_port', type=int)
        self.args, self.unknown = self.parser.parse_known_args(sys.argv[2:])
        # Verify command line arguments
        status = self.verify_args(self.parser.prog, self.args)
        if status != 0:
            exit(status)

    # -- Getters

    # Gets server host
    def get_server_host(self):
        return self.args.server_host

    # Gets server port
    def get_server_port(self):
        return self.args.server_port

    # -- Static methods

    # Verify command line arguments
    @staticmethod
    def verify_args(prog, args):
        if args.server_port and args.server_port not in range(1, 65536):
            print(prog + ': error: arguments -p/--server_port: The port must be between 1 and 65535.', file=sys.stderr)
            return 1
        # Else
        return 0


# Custom parser

class DagdaStartParser(argparse.ArgumentParser):

    # Overrides the error method
    def error(self, message):
        self.print_usage()
        exit(2)

    # Overrides the format help method
    def format_help(self):
        return start_parser_text


# Custom text

start_parser_text = '''usage: dagda.py start [-h] [--server_host SERVER_HOST] [--server_port SERVER_PORT]

The Dagda server.

Optional Arguments:
  -h, --help            show this help message and exit
  -s SERVER_HOST, --server_host SERVER_HOST
                        address/interface where the server binds itself. By
                        default, Dagda server binds to '127.0.0.1'
  -p SERVER_PORT, --server_port SERVER_PORT
                        port where the server binds itself. By default, the
                        Dagda server port is 5000
'''