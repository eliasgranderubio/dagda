import os
import json
import datetime
from flask import Flask
from api.internal.internal_server import InternalServer
from api.service.vuln import vuln_api
from api.service.history import history_api
from vulnDB.db_composer import DBComposer


# Dagda server class

class DagdaServer:

    # -- Global attributes

    app = Flask(__name__)
    app.register_blueprint(history_api)
    app.register_blueprint(vuln_api)

    # -- Public methods

    # DagdaServer Constructor
    def __init__(self, dagda_server_host='127.0.0.1', dagda_server_port=5000, mongodb_host='127.0.0.1',
                 mongodb_port=27017):
        super(DagdaServer, self).__init__()
        self.dagda_server_host = dagda_server_host
        self.dagda_server_port = dagda_server_port
        InternalServer.set_mongodb_driver(mongodb_host, mongodb_port)

    # Runs DagdaServer
    def run(self):
        new_pid = os.fork()
        if new_pid == 0:
            while True:
                item = InternalServer.get_dagda_edn().get()
                if item['msg'] == 'init_db':
                    self._init_or_update_db()
        else:
            DagdaServer.app.run(debug=True, host=self.dagda_server_host, port=self.dagda_server_port)

    # 400 Bad Request error handler
    @app.errorhandler(400)
    def bad_request(self):
        return json.dumps({'err': 400, 'msg': 'Bad Request'}, sort_keys=True), 400

    # 404 Not Found error handler
    @app.errorhandler(404)
    def not_found(self):
        return json.dumps({'err': 404, 'msg': 'Not Found'}, sort_keys=True), 404

    # -- Private methods

    # Init or update the vulnerabilities db
    def _init_or_update_db(self):
        InternalServer.get_mongodb_driver().insert_init_db_process_status(
            {'status': 'Initializing', 'timestamp': datetime.datetime.now().timestamp()})
        # Init db
        db_composer = DBComposer()
        db_composer.compose_vuln_db()
        InternalServer.get_mongodb_driver().insert_init_db_process_status(
            {'status': 'Updated', 'timestamp': datetime.datetime.now().timestamp()})
