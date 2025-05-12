#!/usr/bin/env python3
import sys
from pymongo import MongoClient, UpdateOne
import os
from typing import List, Set, Optional

# Helper to load config file if env var is not set

def load_from_conf(conf_path, key):
    try:
        with open(conf_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k == key:
                    return v
    except Exception:
        pass
    return None

# Try environment variable first
MONGO_URI = os.environ.get("MONGO_URI")
DB_NAME = os.environ.get("DB_NAME")

# If not set, try secrets.conf in current directory
if not MONGO_URI:
    MONGO_URI = load_from_conf("./secrets.conf", "MONGO_URI")
if not DB_NAME:
    DB_NAME = load_from_conf("./secrets.conf", "DB_NAME")
if not DB_NAME:
    DB_NAME = "autoar"

if not MONGO_URI:
    print("Error: MONGO_URI environment variable not set and not found in secrets.conf. Please set it in your config or environment.")
    sys.exit(1)

DOMAINS_COLLECTION = "domains"
SUBDOMAINS_COLLECTION = "subdomains"

def show_help():
    """Display help message with available commands and usage."""
    help_text = """
MongoDB Handler - Manage domains and subdomains

Usage:
    ./mongo_db_handler.py <command> [arguments]

Commands:
    add_domain <domain>                     Add a single domain
    add_subdomain <domain> <subdomain>      Add a single subdomain to a domain
    add_subdomains_file <domain> <file>     Add multiple subdomains from a file
    list_domains                            List all domains
    get_subdomains <domain>                 Get all subdomains for a domain
    help                                    Show this help message

Examples:
    ./mongo_db_handler.py add_domain example.com
    ./mongo_db_handler.py add_subdomain example.com sub.example.com
    ./mongo_db_handler.py add_subdomains_file example.com subdomains.txt
    ./mongo_db_handler.py list_domains
    ./mongo_db_handler.py get_subdomains example.com
    """
    print(help_text)

class DatabaseHandler:
    def __init__(self):
        try:
            self.client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            self.client.admin.command('ping')
            self.db = self.client[DB_NAME]
            # Create indexes for better performance
            self.db[DOMAINS_COLLECTION].create_index("domain", unique=True)
            self.db[SUBDOMAINS_COLLECTION].create_index([("domain_id", 1), ("subdomain", 1)], unique=True)
        except Exception as e:
            print(f"Error connecting to database: {str(e)}")
            sys.exit(1)

    def add_domain(self, domain: str) -> bool:
        """Add a domain to the database."""
        try:
            if not self._is_valid_domain(domain):
                print(f"Error: Invalid domain format: {domain}")
                return False

            result = self.db[DOMAINS_COLLECTION].update_one(
                {"domain": domain}, 
                {"$set": {"domain": domain}}, 
                upsert=True
            )
            return True
        except Exception as e:
            print(f"Error adding domain: {str(e)}")
            return False

    def add_subdomain(self, domain: str, subdomain: str) -> bool:
        """Add a subdomain to a domain."""
        try:
            if not self._is_valid_domain(domain) or not self._is_valid_domain(subdomain):
                print("Error: Invalid domain or subdomain format")
                return False

            if not subdomain.endswith(domain):
                print(f"Error: Subdomain {subdomain} must be part of domain {domain}")
                return False

            if self.add_domain(domain):
                domain_doc = self.db[DOMAINS_COLLECTION].find_one({"domain": domain})
                if domain_doc:
                    self.db[SUBDOMAINS_COLLECTION].update_one(
                        {"domain_id": domain_doc["_id"], "subdomain": subdomain},
                        {"$set": {"domain_id": domain_doc["_id"], "subdomain": subdomain}},
                        upsert=True
                    )
                    return True
            return False
        except Exception as e:
            print(f"Error adding subdomain: {str(e)}")
            return False

    def list_domains(self) -> None:
        """List all domains in the database."""
        try:
            domains = list(self.db[DOMAINS_COLLECTION].find({}, {"domain": 1, "_id": 0}))
            if domains:
                for doc in domains:
                    print(doc['domain'])
            else:
                print("No domains found in database")
        except Exception as e:
            print(f"Error listing domains: {str(e)}")

    def get_subdomains(self, domain: str) -> None:
        """Get all subdomains for a domain."""
        try:
            if not self._is_valid_domain(domain):
                print(f"Error: Invalid domain format: {domain}")
                return

            domain_doc = self.db[DOMAINS_COLLECTION].find_one({"domain": domain})
            if domain_doc:
                subdomains = list(self.db[SUBDOMAINS_COLLECTION].find(
                    {"domain_id": domain_doc["_id"]},
                    {"subdomain": 1, "_id": 0}
                ))
                if subdomains:
                    for doc in subdomains:
                        print(doc['subdomain'])
                else:
                    print(f"No subdomains found for {domain}")
            else:
                print(f"Domain {domain} not found in database")
        except Exception as e:
            print(f"Error getting subdomains: {str(e)}")

    def add_subdomains_from_file(self, domain: str, file_path: str) -> None:
        """Add multiple subdomains from a file using bulk operations."""
        try:
            if not self._is_valid_domain(domain):
                print(f"Error: Invalid domain format: {domain}")
                return

            if not os.path.exists(file_path):
                print(f"Error: File not found: {file_path}")
                return

            # First ensure domain exists and get its ID
            domain_result = self.db[DOMAINS_COLLECTION].update_one(
                {"domain": domain},
                {"$set": {"domain": domain}},
                upsert=True
            )
            
            domain_doc = self.db[DOMAINS_COLLECTION].find_one({"domain": domain})
            if not domain_doc:
                print(f"Error: Could not find or create domain {domain}")
                return

            # Read and validate subdomains
            subdomains = set()
            with open(file_path, 'r') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain and self._is_valid_domain(subdomain):
                        subdomains.add(subdomain)

            if not subdomains:
                print("No valid subdomains found in file")
                return

            # Prepare bulk operations
            bulk_operations = []
            for subdomain in subdomains:
                bulk_operations.append(
                    UpdateOne(
                        {
                            "domain_id": domain_doc["_id"],
                            "subdomain": subdomain
                        },
                        {
                            "$set": {
                                "domain_id": domain_doc["_id"],
                                "subdomain": subdomain
                            }
                        },
                        upsert=True
                    )
                )

            # Execute bulk operation
            if bulk_operations:
                print(f"Processing {len(bulk_operations)} subdomains...")
                result = self.db[SUBDOMAINS_COLLECTION].bulk_write(bulk_operations, ordered=False)
                print(f"Successfully processed {len(subdomains)} subdomains for {domain}")
                print(f"Upserted: {result.upserted_count}, Modified: {result.modified_count}")

        except Exception as e:
            print(f"Error processing file: {str(e)}")

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """Basic domain validation."""
        if not domain:
            return False
        if not '.' in domain:
            return False
        if len(domain) < 4:
            return False
        if not all(c.isalnum() or c in '.-' for c in domain):
            return False
        return True

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help', 'help']:
        show_help()
        sys.exit(0)

    handler = DatabaseHandler()
    cmd = sys.argv[1]

    try:
        if cmd == "add_domain" and len(sys.argv) == 3:
            handler.add_domain(sys.argv[2])
        elif cmd == "add_subdomain" and len(sys.argv) == 4:
            handler.add_subdomain(sys.argv[2], sys.argv[3])
        elif cmd == "list_domains":
            handler.list_domains()
        elif cmd == "get_subdomains" and len(sys.argv) == 3:
            handler.get_subdomains(sys.argv[2])
        elif cmd == "add_subdomains_file" and len(sys.argv) == 4:
            handler.add_subdomains_from_file(sys.argv[2], sys.argv[3])
        else:
            print("Error: Invalid command or wrong number of arguments")
            show_help()
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
