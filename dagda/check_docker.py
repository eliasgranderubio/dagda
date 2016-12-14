import datetime
import json
from analysis.analyzer import Analyzer
from driver.mongodb_driver import MongoDbDriver
from cli.check_docker_cli_parser import CheckDockerCLIParser


# Main function
def main(parsed_args):
    m = MongoDbDriver()
    analyzer = Analyzer()
    # Evaluate the docker image
    evaluated_docker_image = analyzer.evaluate_image(parsed_args.get_docker_image_name(),
                                                     parsed_args.get_container_id())
    # Update the scan history
    m.insert_docker_image_scan_result_to_history(evaluated_docker_image)
    # Prepares output
    evaluated_docker_image['timestamp'] = str(
        datetime.datetime.utcfromtimestamp(evaluated_docker_image['timestamp']))
    del evaluated_docker_image['_id']
    print(json.dumps(evaluated_docker_image, sort_keys=True, indent=4))


if __name__ == "__main__":
    main(CheckDockerCLIParser())
