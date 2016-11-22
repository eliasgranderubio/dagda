from util.vuln_db_cli_parser import VulnDBCLIParser
from vulnDB.db_composer import DBComposer
from vulnDB.mongodb_driver import MongoDbDriver
import json


# Main function
def main(parsed_args):
    if parsed_args.is_initialization_required():
        # Init db
        db_composer = DBComposer()
        db_composer.compose_vuln_db()
    elif parsed_args.get_cve():
        # Get product from CVE
        m = MongoDbDriver()
        print(json.dumps(m.get_products_from_CVE(parsed_args.get_cve()), sort_keys=True, indent=4))
    elif parsed_args.get_bid():
        # Get product from BID
        m = MongoDbDriver()
        print(json.dumps(m.get_products_from_BID(parsed_args.get_bid()), sort_keys=True, indent=4))
    elif parsed_args.get_exploit_db_id():
        # Get product from Exploit DB Id
        m = MongoDbDriver()
        print(json.dumps(m.get_products_from_exploit_db_id(parsed_args.get_exploit_db_id()), sort_keys=True, indent=4))
    else:
        m = MongoDbDriver()
        if parsed_args.is_only_product_check():
            # Checks if vulnerabilities exists
            print(m.has_vulnerabilities(parsed_args.get_product(), parsed_args.get_product_version()))
        else:
            # Gets CVEs, BIDs and Exploit_DB Ids
            print(json.dumps(m.get_vulnerabilities(parsed_args.get_product(), parsed_args.get_product_version()),
                             sort_keys=True, indent=4))


if __name__ == "__main__":
    main(VulnDBCLIParser())
