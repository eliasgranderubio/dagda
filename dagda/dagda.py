import datetime
import json
from analysis.analyzer import Analyzer
from driver.mongodb_driver import MongoDbDriver
from cli.dagda_cli_parser import DagdaCLIParser
from vulnDB.db_composer import DBComposer
from api.dagda_server import DagdaServer


# Main function
def main(parsed_args):
    # Init
    m = MongoDbDriver()
    cmd = parsed_args.get_command()
    parsed_args = parsed_args.get_extra_args()

    # Executes vuln sub-command
    if cmd == 'vuln':
        if parsed_args.is_initialization_required():
            # Init db
            db_composer = DBComposer()
            db_composer.compose_vuln_db()
        else:
            if parsed_args.get_cve():
                # Gets products by CVE
                print(json.dumps(m.get_products_by_cve(parsed_args.get_cve()), sort_keys=True, indent=4))
            elif parsed_args.get_bid():
                # Gets products by BID
                print(json.dumps(m.get_products_by_bid(parsed_args.get_bid()), sort_keys=True, indent=4))
            elif parsed_args.get_exploit_db_id():
                # Gets products by Exploit DB Id
                print(json.dumps(m.get_products_by_exploit_db_id(parsed_args.get_exploit_db_id()),
                                 sort_keys=True, indent=4))
            else:
                # Gets CVEs, BIDs and Exploit_DB Ids by product and version
                print(json.dumps(m.get_vulnerabilities(parsed_args.get_product(), parsed_args.get_product_version()),
                                 sort_keys=True, indent=4))

    # Executes check sub-command
    elif cmd == 'check':
        analyzer = Analyzer()
        # Evaluates the docker image
        evaluated_docker_image = analyzer.evaluate_image(parsed_args.get_docker_image_name(),
                                                         parsed_args.get_container_id())
        # Updates the scan history
        m.insert_docker_image_scan_result_to_history(evaluated_docker_image)
        # Prepares output
        evaluated_docker_image['timestamp'] = str(
            datetime.datetime.utcfromtimestamp(evaluated_docker_image['timestamp']))
        del evaluated_docker_image['_id']
        print(json.dumps(evaluated_docker_image, sort_keys=True, indent=4))

    # Executes history sub-command
    elif cmd == 'history':
        # Gets the history
        print(json.dumps(m.get_docker_image_history(parsed_args.get_docker_image_name()), sort_keys=True, indent=4))

    # Executes start sub-command
    elif cmd == 'start':
        ds = DagdaServer(parsed_args.get_server_host(), parsed_args.get_server_port())
        ds.run()


if __name__ == "__main__":
    main(DagdaCLIParser())
