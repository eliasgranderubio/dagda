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

import json
from cli.dagda_cli import execute_dagda_cmd
from cli.dagda_cli_parser import DagdaCLIParser
from log.dagda_logger import DagdaLogger


# -- Main function
def main(parsed_args):
    # -- Init
    cmd = parsed_args.get_command()
    parsed_args = parsed_args.get_extra_args()

    try:
        # Execute Dagda command
        r = execute_dagda_cmd(cmd=cmd, args=parsed_args)

        # -- Print cmd output
        if r is not None and r.content:
            output = r.content.decode('utf-8')
            try:
                print(json.dumps(json.loads(output), sort_keys=True, indent=4))
            except json.decoder.JSONDecodeError as err:
                DagdaLogger.get_logger().error('JSONDecodeError with the received response: "' + output + '"')
                DagdaLogger.get_logger().error(str(err))
    except BaseException as err:
        DagdaLogger.get_logger().error(str(err))


if __name__ == "__main__":
    main(DagdaCLIParser())
