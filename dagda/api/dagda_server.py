from flask import Flask
from api.service.vuln import vuln_api


# Dagda server class

class DagdaServer:

    # -- Global attributes

    app = Flask(__name__)
    app.register_blueprint(vuln_api)

    # -- Public methods

    # DagdaServer Constructor
    def __init__(self, dagda_server_host='127.0.0.1', dagda_server_port=5000):
        super(DagdaServer, self).__init__()
        self.dagda_server_host = dagda_server_host
        self.dagda_server_port = dagda_server_port

    # Runs DagdaServer
    def run(self):
        DagdaServer.app.run(debug=True, host=self.dagda_server_host, port=self.dagda_server_port)

    # 400 Bad Request error handler
    @app.errorhandler(400)
    def bad_request(self):
        return '', 400

    # 404 Not Found error handler
    @app.errorhandler(404)
    def not_found(self):
        return '', 404
