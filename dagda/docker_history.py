import json
from driver.mongodb_driver import MongoDbDriver
from cli.docker_history_cli_parser import DockerHistoryCLIParser


# Main function
def main(parsed_args):
    m = MongoDbDriver()
    # Gets the history
    print(json.dumps(m.get_docker_image_history(parsed_args.get_docker_image_name()), sort_keys=True, indent=4))


if __name__ == "__main__":
    main(DockerHistoryCLIParser())
