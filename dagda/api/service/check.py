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
import pathlib
import datetime
from flask import Blueprint, request
from werkzeug.utils import secure_filename
from exception.dagda_error import DagdaError
from log.dagda_logger import DagdaLogger
from api.internal.internal_server import InternalServer
import uuid

# -- Global

check_api = Blueprint("check_api", __name__)

# Check docker by tar
@check_api.route("/v1/check/images/tar/<path:image_name>", methods=["POST"])
def check_docker_by_image_tar(image_name):
    return check_docker(image_name, request, True)


# Check docker by image name
@check_api.route("/v1/check/images/<path:image_name>", methods=["POST"])
def check_docker_by_image_name(image_name):
    return check_docker(image_name, request, False)


def check_docker(image_name, request, is_already_tar):
    # -- Check input
    uploaded_file = None

    DagdaLogger.get_logger().info("image_name: " + str(image_name))

    if is_already_tar:
        extension = pathlib.Path(image_name).suffix
        try:
            uploaded_file = f"/tmp/{uuid.uuid4()}{extension}"
            with open(uploaded_file, "bw") as f:
                chunk_size = 4096
                while True:
                    chunk = request.stream.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    f.write(chunk)
            image_name = image_name if image_name else "unknown"  # TODO
            is_already_tar = True
        except Exception as ex:
            message = "Unexpected exception of type {0} occurred while unpacking the docker tar file: {1!r}".format(
                type(ex).__name__,
                ex.get_message() if type(ex).__name__ == "DagdaError" else ex.args,
            )
            DagdaLogger.get_logger().error(message)
            return json.dumps({"err": 500, "msg": message}, sort_keys=True), 500

    elif not image_name:
        return json.dumps({"err": 400, "msg": "Bad image name"}, sort_keys=True), 400

    # -- Docker pull from remote registry if it is necessary
    try:
        pulled = False
        if is_already_tar:
            pass
        elif not InternalServer.get_docker_driver().is_docker_image(image_name):
            if ":" in image_name:
                tmp = image_name.split(":")[0]
                tag = image_name.split(":")[1]
                msg = "Error: image library/" + image_name + ":" + tag + " not found"
                output = InternalServer.get_docker_driver().docker_pull(tmp, tag=tag)
            else:
                msg = "Error: image library/" + image_name + ":latest not found"
                output = InternalServer.get_docker_driver().docker_pull(image_name)
            if "errorDetail" in output:
                DagdaLogger.get_logger().error(msg)
                raise DagdaError(msg)
            pulled = True
    except Exception as ex:
        message = "Unexpected exception of type {0} occurred while pulling the docker image: {1!r}".format(
            type(ex).__name__,
            ex.get_message() if type(ex).__name__ == "DagdaError" else ex.args,
        )
        DagdaLogger.get_logger().error(message)
        return (
            json.dumps({"err": 404, "msg": "Image name not found"}, sort_keys=True),
            404,
        )

    # -- Process request
    data = {}
    data["image_name"] = image_name
    data["timestamp"] = datetime.datetime.now().timestamp()
    data["status"] = "Analyzing"
    id = InternalServer.get_mongodb_driver().insert_docker_image_scan_result_to_history(
        data
    )
    edn_data = {"image_name": image_name, "_id": str(id), "pulled": pulled}
    msg = "check_image"
    if is_already_tar:
        msg = "check_image_tar"
        edn_data["path"] = uploaded_file
    edn_data["msg"] = msg
    InternalServer.get_dagda_edn().put(edn_data)

    # -- Return
    output = {}
    output["id"] = str(id)
    output["msg"] = "Accepted the analysis of <" + image_name + ">"
    return json.dumps(output, sort_keys=True), 202


# Check docker by container id
@check_api.route("/v1/check/containers/<string:container_id>", methods=["POST"])
def check_docker_by_container_id(container_id):
    # -- Check input
    if not container_id:
        return json.dumps({"err": 400, "msg": "Bad container id"}, sort_keys=True), 400

    # -- Retrieves docker image name
    try:
        image_name = (
            InternalServer.get_docker_driver().get_docker_image_name_by_container_id(
                container_id
            )
        )
    except Exception as ex:
        message = "Unexpected exception of type {0} occurred while getting the docker image name: {1!r}".format(
            type(ex).__name__,
            ex.get_message() if type(ex).__name__ == "DagdaError" else ex.args,
        )
        DagdaLogger.get_logger().error(message)
        return (
            json.dumps({"err": 404, "msg": "Container Id not found"}, sort_keys=True),
            404,
        )

    # -- Process request
    data = {}
    data["image_name"] = image_name
    data["timestamp"] = datetime.datetime.now().timestamp()
    data["status"] = "Analyzing"
    id = InternalServer.get_mongodb_driver().insert_docker_image_scan_result_to_history(
        data
    )
    InternalServer.get_dagda_edn().put(
        {"msg": "check_container", "container_id": container_id, "_id": str(id)}
    )

    # -- Return
    output = {}
    output["id"] = str(id)
    output["msg"] = (
        "Accepted the analysis of <" + image_name + "> with id: " + container_id
    )
    return json.dumps(output, sort_keys=True), 202
