import json
from driver.mongodb_driver import MongoDbDriver
from cli.vuln_db_cli_parser import VulnDBCLIParser
from vulnDB.db_composer import DBComposer


# Main function
def main(parsed_args):
    if parsed_args.is_initialization_required():
        # Init db
        db_composer = DBComposer()
        db_composer.compose_vuln_db()
    else:
        m = MongoDbDriver()
        if parsed_args.get_cve():
            # Get product from CVE
            print(json.dumps(m.get_products_from_cve(parsed_args.get_cve()), sort_keys=True, indent=4))
        elif parsed_args.get_bid():
            # Get product from BID
            print(json.dumps(m.get_products_from_bid(parsed_args.get_bid()), sort_keys=True, indent=4))
        elif parsed_args.get_exploit_db_id():
            # Get product from Exploit DB Id
            print(json.dumps(m.get_products_from_exploit_db_id(parsed_args.get_exploit_db_id()),
                             sort_keys=True, indent=4))
        else:
            # Gets CVEs, BIDs and Exploit_DB Ids
            print(json.dumps(m.get_vulnerabilities(parsed_args.get_product(), parsed_args.get_product_version()),
                             sort_keys=True, indent=4))


if __name__ == "__main__":
    main(VulnDBCLIParser())
