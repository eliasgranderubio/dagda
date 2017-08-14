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
from log.dagda_logger import DagdaLogger


class HistoryCLIParser:

    # -- Public methods

    # HistoryCLIParser Constructor
    def __init__(self):
        super(HistoryCLIParser, self).__init__()
        self.parser = DagdaHistoryParser(prog='dagda.py history', usage=history_parser_text)
        self.parser.add_argument('docker_image_name', metavar='IMAGE_NAME', type=str, nargs='?')
        self.parser.add_argument('--id', type=str)
        self.parser.add_argument('--fp', nargs='+', type=str)
        self.parser.add_argument('--is_fp', nargs='+', type=str)
        self.args, self.unknown = self.parser.parse_known_args(sys.argv[2:])
        # Verify command line arguments
        status = self.verify_args(self.args)
        if status != 0:
            exit(status)

    # -- Getters

    # Gets docker image name
    def get_docker_image_name(self):
        return self.args.docker_image_name

    # Gets report id
    def get_report_id(self):
        return self.args.id

    # Gets product and version for setting as false positive
    def get_fp(self):
        if self.args.fp:
            return HistoryCLIParser._parse_product_and_version(self.args.fp)
        return None

    # Gets product and version for checking if it is a false positive
    def get_is_fp(self):
        if self.args.is_fp:
            return HistoryCLIParser._parse_product_and_version(self.args.is_fp)
        return None

    # -- Static methods

    # Verify command line arguments
    @staticmethod
    def verify_args(args):
        if args.fp and (args.id or args.is_fp):
            DagdaLogger.get_logger().error('Argument --fp: this argument must be alone.')
            return 1
        elif args.fp and not args.docker_image_name:
            DagdaLogger.get_logger().error('Argument --fp: IMAGE_NAME argument is mandatory.')
            return 2
        elif args.is_fp and args.id:
            DagdaLogger.get_logger().error('Argument --is_fp: this argument must be alone.')
            return 3
        elif args.is_fp and not args.docker_image_name:
            DagdaLogger.get_logger().error('Argument --is_fp: IMAGE_NAME argument is mandatory.')
            return 4
        return 0

    # Parse product and version from CLI argument
    @staticmethod
    def _parse_product_and_version(fp):
        output = ''
        if fp:
            for s in fp:
                output += ' ' + s
            output = output.rstrip().lstrip()
            if ':' in output:
                output = output.split(':')
                return output[0], output[1]
            else:
                return output, None
        return None


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

history_parser_text = '''usage: dagda.py history [-h] [IMAGE_NAME] [--fp PRODUCT_NAME[:PRODUCT_VERSION]]
                  [--is_fp PRODUCT_NAME[:PRODUCT_VERSION]] [--id REPORT_ID]

Your personal docker security analyzer history.

Positional Arguments:
  IMAGE_NAME            the full analysis history for the requested docker image name
                        will be shown ordered by descending date. If the image name is
                        not present, a full analysis history resume will be shown

Optional Arguments:
  -h, --help            show this help message and exit
  --id REPORT_ID        the report with this id will be shown
  
  --fp PRODUCT_NAME[:PRODUCT_VERSION]
                        tags the product vulnerability as false positive. Both,
                        "<PRODUCT_NAME>" and "<PRODUCT_NAME>:<PRODUCT_VERSION>" are 
                        accepted
                        
  --is_fp PRODUCT_NAME[:PRODUCT_VERSION]
                        checks if the product vulnerability is a false positive. Both,
                        "<PRODUCT_NAME>" and "<PRODUCT_NAME>:<PRODUCT_VERSION>" are 
                        accepted      
'''
