from util.cve_db_cli_parser import CVEDBCLIParser
from cveDB.db_composer import DBComposer
from cveDB.mongodb_driver import MongoDbDriver
import json


# Main function
def main(parsed_args):
    if parsed_args.is_initialization_required():
        # Init db
        db_composer = DBComposer()
        db_composer.compose_cve_db()
    elif parsed_args.get_cve():
        # Get product from CVE
        m = MongoDbDriver()
        print(json.dumps(m.get_products(parsed_args.get_cve()), sort_keys=True, indent=4))
    else:
        m = MongoDbDriver()
        if parsed_args.is_only_product_check():
            # Checks if cves exists
            print(m.has_cves(parsed_args.get_product(), parsed_args.get_product_version()))
        else:
            # Gets cves
            print(json.dumps(m.get_cves(parsed_args.get_product(), parsed_args.get_product_version()), sort_keys=True,
                             indent=4))


if __name__ == "__main__":
    main(CVEDBCLIParser())
