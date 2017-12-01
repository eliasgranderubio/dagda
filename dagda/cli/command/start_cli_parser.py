#
# Licensed to Dagda under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Dagda licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

import argparse
import sys
import yaml
from log.dagda_logger import DagdaLogger


class StartCLIParser:

    # -- Public methods

    # StartCLIParser Constructor
    def __init__(self):
        super(StartCLIParser, self).__init__()
        self.parser = DagdaStartParser(prog='dagda.py start', usage=start_parser_text)
        self.parser.add_argument('-s', '--server_host', type=str)
        self.parser.add_argument('-p', '--server_port', type=int)
        self.parser.add_argument('-m', '--mongodb_host', type=str)
        self.parser.add_argument('-mp', '--mongodb_port', type=int)
        self.parser.add_argument('--mongodb_ssl', action='store_true')
        self.parser.add_argument('--mongodb_user', type=str)
        self.parser.add_argument('--mongodb_pass', type=str)
        self.parser.add_argument('--falco_rules_file', type=argparse.FileType('r'))
        self.args, self.unknown = self.parser.parse_known_args(sys.argv[2:])
        # Verify command line arguments
        status = self.verify_args(self.args)
        if status != 0:
            exit(status)

    # -- Getters

    # Gets server host
    def get_server_host(self):
        return self.args.server_host

    # Gets server port
    def get_server_port(self):
        return self.args.server_port

    # Gets mongodb host
    def get_mongodb_host(self):
        return self.args.mongodb_host

    # Gets mongodb port
    def get_mongodb_port(self):
        return self.args.mongodb_port

    # Gets if mongodb ssl is enabled
    def is_mongodb_ssl_enabled(self):
        return self.args.mongodb_ssl

    # Gets mongodb user
    def get_mongodb_user(self):
        return self.args.mongodb_user

    # Gets mongodb pass
    def get_mongodb_pass(self):
        return self.args.mongodb_pass

    # Gets falco rules
    def get_falco_rules_filename(self):
        if self.args.falco_rules_file is None:
            return None
        else:
            return self.args.falco_rules_file.name

    # -- Static methods

    # Verify command line arguments
    @staticmethod
    def verify_args(args):
        if args.server_port and args.server_port not in range(1, 65536):
            DagdaLogger.get_logger().error('Argument -p/--server_port: The port must be between 1 and 65535.')
            return 1
        elif args.mongodb_port and args.mongodb_port not in range(1, 65536):
            DagdaLogger.get_logger().error('Argument -mp/--mongodb_port: The port must be between 1 and 65535.')
            return 2
        elif args.mongodb_user and not args.mongodb_pass:
            DagdaLogger.get_logger().error('Argument --mongodb_pass: this argument should not be empty if you set '
                                           '"--mongodb_user".')
            return 3
        elif args.mongodb_pass and not args.mongodb_user:
            DagdaLogger.get_logger().error('Argument --mongodb_user: this argument should not be empty if you set '
                                           '"--mongodb_pass".')
            return 4
        elif args.falco_rules_file:
            with args.falco_rules_file as content_file:
                try:
                    yaml.safe_load(content_file.read())
                except:
                    DagdaLogger.get_logger().error('Argument --falco_rules_file: Malformed yaml file.')
                    return 5
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
                  [--mongodb_host MONGODB_HOST] [--mongodb_port MONGODB_PORT]
                  [--mongodb_ssl] [--mongodb_user MONGODB_USER] [--mongodb_pass MONGODB_PASS]
                  [--falco_rules_file RULES_FILE]

The Dagda server.

Optional Arguments:
  -h, --help            show this help message and exit

  -s SERVER_HOST, --server_host SERVER_HOST
                        address/interface where the server binds itself. By
                        default, Dagda server binds to '127.0.0.1'

  -p SERVER_PORT, --server_port SERVER_PORT
                        port where the server binds itself. By default, the
                        Dagda server port is 5000

  -m MONGODB_HOST, --mongodb_host MONGODB_HOST
                        address/interface where the MongoDB is listening. By
                        default, MongoDB server is set to '127.0.0.1'

  -mp MONGODB_PORT, --mongodb_port MONGODB_PORT
                        port where the MongoDB is listening. By default, the
                        MongoDB port is set to 27017

  --mongodb_ssl         creates the connection to the MongoDB server using
                        SSL/TLS. By default, SSL/TLS connection is disabled

  --mongodb_user        username for basic authentication with MongoDB. By
                        default, authentication is disabled
  --mongodb_pass        password for basic authentication with MongoDB. By
                        default, authentication is disabled

  --falco_rules_file    sysdig/falco custom rules file (See 'Falco Rules' wiki
                        page [https://github.com/draios/falco/wiki/Falco-Rules]
                        for details)
'''