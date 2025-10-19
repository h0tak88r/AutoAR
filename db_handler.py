#!/usr/bin/env python3
"""
AutoAR Database Handler
A Python script to handle all database operations for AutoAR.
This replaces the shell-based database operations for better reliability.
"""

import os
import sys
import argparse
import psycopg2
from psycopg2.extras import RealDictCursor
import json
from datetime import datetime
from urllib.parse import urlparse

class AutoARDB:
    def __init__(self):
        """Initialize database connection."""
        self.conn = None
        self.connect()
    
    def connect(self):
        """Connect to PostgreSQL database."""
        try:
            # Debug: Print environment info in Docker
            if os.path.exists('/.dockerenv'):
                print(f"[DEBUG] Running in Docker container", file=sys.stderr)
            
            # Check for connection string in DB_CONNECTION_STRING or DB_HOST
            conn_str = os.getenv('DB_CONNECTION_STRING', '')
            if not conn_str:
                conn_str = os.getenv('DB_HOST', '')
            
            print(f"[DEBUG] Connection string: {conn_str[:50]}..." if len(conn_str) > 50 else f"[DEBUG] Connection string: {conn_str}", file=sys.stderr)
            
            if conn_str and conn_str.startswith('postgresql://'):
                # Use the connection string directly
                self.conn = psycopg2.connect(conn_str)
            else:
                # Fallback to individual environment variables
                host = os.getenv('DB_HOST', 'localhost')
                port = os.getenv('DB_PORT', '5432')
                user = os.getenv('DB_USER', 'postgres')
                password = os.getenv('DB_PASSWORD', '')
                database = os.getenv('DB_NAME', 'autoar')
                
                conn_str = f"host={host} port={port} user={user} password={password} dbname={database}"
                self.conn = psycopg2.connect(conn_str)
            
            self.conn.autocommit = True
            print(f"[DEBUG] Connected to database successfully", file=sys.stderr)
            
        except Exception as e:
            print(f"[ERROR] Failed to connect to database: {e}", file=sys.stderr)
            sys.exit(1)
    
    def execute_query(self, query, params=None):
        """Execute a query and return results."""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                if cur.description:
                    return cur.fetchall()
                return []
        except Exception as e:
            print(f"[ERROR] Query failed: {e}", file=sys.stderr)
            print(f"[ERROR] Query: {query}", file=sys.stderr)
            return None
    
    def execute_command(self, query, params=None):
        """Execute a command (INSERT, UPDATE, DELETE) and return success status."""
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, params)
                return True
        except Exception as e:
            print(f"[ERROR] Command failed: {e}", file=sys.stderr)
            print(f"[ERROR] Query: {query}", file=sys.stderr)
            return False
    
    def insert_domain(self, domain):
        """Insert a domain and return its ID."""
        query = """
        INSERT INTO domains (domain, created_at, updated_at)
        VALUES (%s, NOW(), NOW())
        ON CONFLICT (domain) DO UPDATE SET updated_at = NOW()
        RETURNING id;
        """
        result = self.execute_query(query, (domain,))
        if result:
            domain_id = result[0]['id']
            print(f"[DEBUG] Domain '{domain}' has ID: {domain_id}", file=sys.stderr)
            return domain_id
        return None
    
    def insert_subdomain(self, domain_id, subdomain, is_live=False, http_url='', https_url='', http_status=0, https_status=0):
        """Insert a subdomain and return its ID."""
        query = """
        INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
        ON CONFLICT (subdomain) DO UPDATE SET
            domain_id = EXCLUDED.domain_id,
            is_live = EXCLUDED.is_live,
            http_url = EXCLUDED.http_url,
            https_url = EXCLUDED.https_url,
            http_status = EXCLUDED.http_status,
            https_status = EXCLUDED.https_status,
            updated_at = NOW()
        RETURNING id;
        """
        result = self.execute_query(query, (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status))
        if result:
            return result[0]['id']
        return None
    
    def batch_insert_subdomains(self, domain, subdomains_file, is_live=False):
        """Batch insert subdomains from a file."""
        domain_id = self.insert_domain(domain)
        if not domain_id:
            print(f"[ERROR] Failed to get domain ID for {domain}", file=sys.stderr)
            return False
        
        print(f"[INFO] Batch inserting subdomains for {domain} (domain_id: {domain_id})", file=sys.stderr)
        
        count = 0
        failed = 0
        
        try:
            with open(subdomains_file, 'r') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain:
                        subdomain_id = self.insert_subdomain(domain_id, subdomain, is_live)
                        if subdomain_id:
                            count += 1
                        else:
                            failed += 1
                            print(f"[WARN] Failed to insert subdomain: {subdomain}", file=sys.stderr)
        except FileNotFoundError:
            print(f"[ERROR] Subdomains file not found: {subdomains_file}", file=sys.stderr)
            return False
        
        if count > 0:
            print(f"[OK] Batch inserted {count} subdomains", file=sys.stderr)
        if failed > 0:
            print(f"[WARN] Failed to insert {failed} subdomains", file=sys.stderr)
        
        return count > 0
    
    def insert_js_file(self, domain, js_url, content_hash=''):
        """Insert a JS file and return success status."""
        # Extract subdomain from URL
        parsed = urlparse(js_url)
        subdomain = parsed.hostname
        
        print(f"[DEBUG] domain={domain}, subdomain={subdomain}, js_url={js_url}", file=sys.stderr)
        
        # Get domain ID
        domain_id = self.insert_domain(domain)
        if not domain_id:
            print(f"[ERROR] Failed to get domain ID for {domain}", file=sys.stderr)
            return False
        
        # Get or create subdomain
        subdomain_id = self.insert_subdomain(domain_id, subdomain, False)
        if not subdomain_id:
            print(f"[ERROR] Failed to get subdomain ID for {subdomain}", file=sys.stderr)
            return False
        
        print(f"[DEBUG] subdomain_id={subdomain_id}", file=sys.stderr)
        
        # Insert JS file
        query = """
        INSERT INTO js_files (subdomain_id, js_url, content_hash, last_scanned, created_at, updated_at)
        VALUES (%s, %s, %s, NOW(), NOW(), NOW())
        ON CONFLICT (js_url) DO UPDATE SET
            content_hash = EXCLUDED.content_hash,
            last_scanned = NOW(),
            updated_at = NOW();
        """
        
        success = self.execute_command(query, (subdomain_id, js_url, content_hash))
        if success:
            print(f"[DEBUG] Successfully inserted JS file: {js_url}", file=sys.stderr)
        else:
            print(f"[ERROR] Failed to insert JS file: {js_url}", file=sys.stderr)
        
        return success
    
    def get_domains(self):
        """Get all domains from database."""
        query = "SELECT id, domain, created_at FROM domains ORDER BY domain;"
        result = self.execute_query(query)
        return result if result else []
    
    def get_subdomains(self, domain):
        """Get all subdomains for a domain."""
        query = """
        SELECT s.subdomain, s.is_live, s.http_url, s.https_url, s.http_status, s.https_status
        FROM subdomains s 
        JOIN domains d ON s.domain_id = d.id 
        WHERE d.domain = %s 
        ORDER BY s.subdomain;
        """
        result = self.execute_query(query, (domain,))
        return result if result else []
    
    def get_all_subdomains(self):
        """Get all subdomains from all domains."""
        query = """
        SELECT d.domain, s.subdomain, s.is_live, s.http_url, s.https_url
        FROM subdomains s 
        JOIN domains d ON s.domain_id = d.id 
        ORDER BY d.domain, s.subdomain;
        """
        result = self.execute_query(query)
        return result if result else []
    
    def delete_domain(self, domain, force=False):
        """Delete a domain and all related data."""
        if not force:
            print(f"[WARN] This will delete domain '{domain}' and ALL related data (subdomains, JS files, etc.)", file=sys.stderr)
            print(f"[WARN] Use --force flag to skip this confirmation", file=sys.stderr)
            return False
        
        # Get domain ID
        query = "SELECT id FROM domains WHERE domain = %s;"
        result = self.execute_query(query, (domain,))
        if not result:
            print(f"[ERROR] Domain '{domain}' not found", file=sys.stderr)
            return False
        
        domain_id = result[0]['id']
        
        # Delete JS files
        js_query = """
        DELETE FROM js_files WHERE subdomain_id IN (
            SELECT id FROM subdomains WHERE domain_id = %s
        );
        """
        self.execute_command(js_query, (domain_id,))
        
        # Delete subdomains
        sub_query = "DELETE FROM subdomains WHERE domain_id = %s;"
        self.execute_command(sub_query, (domain_id,))
        
        # Delete domain
        domain_query = "DELETE FROM domains WHERE id = %s;"
        success = self.execute_command(domain_query, (domain_id,))
        
        if success:
            print(f"[OK] Successfully deleted domain '{domain}' and all related data", file=sys.stderr)
        else:
            print(f"[ERROR] Failed to delete domain '{domain}'", file=sys.stderr)
        
        return success
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

def main():
    parser = argparse.ArgumentParser(description='AutoAR Database Handler')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Insert domain command
    insert_domain_parser = subparsers.add_parser('insert-domain', help='Insert a domain')
    insert_domain_parser.add_argument('domain', help='Domain to insert')
    
    # Batch insert subdomains command
    batch_subs_parser = subparsers.add_parser('batch-insert-subdomains', help='Batch insert subdomains')
    batch_subs_parser.add_argument('domain', help='Domain name')
    batch_subs_parser.add_argument('file', help='File containing subdomains')
    batch_subs_parser.add_argument('--live', action='store_true', help='Mark subdomains as live')
    
    # Insert JS file command
    insert_js_parser = subparsers.add_parser('insert-js-file', help='Insert a JS file')
    insert_js_parser.add_argument('domain', help='Domain name')
    insert_js_parser.add_argument('js_url', help='JS file URL')
    insert_js_parser.add_argument('--hash', default='', help='Content hash')
    
    # Get domains command
    get_domains_parser = subparsers.add_parser('get-domains', help='Get all domains')
    
    # Get subdomains command
    get_subs_parser = subparsers.add_parser('get-subdomains', help='Get subdomains for a domain')
    get_subs_parser.add_argument('domain', help='Domain name')
    
    # Get all subdomains command
    get_all_subs_parser = subparsers.add_parser('get-all-subdomains', help='Get all subdomains')
    
    # Delete domain command
    delete_domain_parser = subparsers.add_parser('delete-domain', help='Delete a domain')
    delete_domain_parser.add_argument('domain', help='Domain to delete')
    delete_domain_parser.add_argument('--force', action='store_true', help='Skip confirmation')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Load environment variables from .env file
    env_file = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    # Only set if not already set (preserve existing env vars)
                    if key not in os.environ:
                        os.environ[key] = value
    
    db = AutoARDB()
    
    try:
        if args.command == 'insert-domain':
            domain_id = db.insert_domain(args.domain)
            if domain_id:
                print(domain_id)
            else:
                sys.exit(1)
        
        elif args.command == 'batch-insert-subdomains':
            success = db.batch_insert_subdomains(args.domain, args.file, args.live)
            sys.exit(0 if success else 1)
        
        elif args.command == 'insert-js-file':
            success = db.insert_js_file(args.domain, args.js_url, args.hash)
            sys.exit(0 if success else 1)
        
        elif args.command == 'get-domains':
            domains = db.get_domains()
            for domain in domains:
                print(f"{domain['id']}|{domain['domain']}|{domain['created_at']}")
        
        elif args.command == 'get-subdomains':
            subdomains = db.get_subdomains(args.domain)
            for sub in subdomains:
                print(f"{sub['subdomain']}|{sub['is_live']}|{sub['http_url']}|{sub['https_url']}")
        
        elif args.command == 'get-all-subdomains':
            subdomains = db.get_all_subdomains()
            for sub in subdomains:
                print(f"{sub['domain']}|{sub['subdomain']}|{sub['is_live']}|{sub['http_url']}|{sub['https_url']}")
        
        elif args.command == 'delete-domain':
            success = db.delete_domain(args.domain, args.force)
            sys.exit(0 if success else 1)
    
    finally:
        db.close()

if __name__ == '__main__':
    main()
