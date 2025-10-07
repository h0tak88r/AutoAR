#!/usr/bin/env python3
"""
SQLite Database Handler for AutoAR
Manages domains, subdomains, and JS file URLs storage
"""

import sqlite3
import json
import sys
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

class AutoARDatabase:
    def __init__(self, db_path: str = "autoar.db"):
        """Initialize database connection and create tables if they don't exist"""
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Create database tables if they don't exist"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create domains table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    scan_count INTEGER DEFAULT 0
                )
            ''')
            
            # Create subdomains table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    subdomain TEXT NOT NULL,
                    is_live BOOLEAN DEFAULT FALSE,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (domain_id) REFERENCES domains (id),
                    UNIQUE(domain_id, subdomain)
                )
            ''')
            
            # Create js_files table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS js_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    url TEXT NOT NULL,
                    size INTEGER DEFAULT 0,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (domain_id) REFERENCES domains (id),
                    UNIQUE(domain_id, url)
                )
            ''')
            
            # Create scan_history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    scan_type TEXT NOT NULL,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    subdomains_found INTEGER DEFAULT 0,
                    js_files_found INTEGER DEFAULT 0,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    FOREIGN KEY (domain_id) REFERENCES domains (id)
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_js_files_domain ON js_files(domain_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_history_domain ON scan_history(domain_id)')
            
            conn.commit()
    
    def get_or_create_domain(self, domain: str) -> int:
        """Get domain ID or create new domain entry"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Try to get existing domain
            cursor.execute('SELECT id FROM domains WHERE domain = ?', (domain,))
            result = cursor.fetchone()
            
            if result:
                domain_id = result[0]
                # Update last_scan and scan_count
                cursor.execute('''
                    UPDATE domains 
                    SET last_scan = CURRENT_TIMESTAMP, scan_count = scan_count + 1 
                    WHERE id = ?
                ''', (domain_id,))
                return domain_id
            else:
                # Create new domain
                cursor.execute('INSERT INTO domains (domain) VALUES (?)', (domain,))
                return cursor.lastrowid
    
    def add_subdomains_file(self, domain: str, subdomains_file: str):
        """Add subdomains from file to database"""
        if not os.path.exists(subdomains_file):
            print(f"Error: Subdomains file {subdomains_file} not found")
            return
        
        domain_id = self.get_or_create_domain(domain)
        subdomains_added = 0
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            with open(subdomains_file, 'r') as f:
                for line in f:
                    subdomain = line.strip()
                    if not subdomain:
                        continue
                    
                    try:
                        cursor.execute('''
                            INSERT OR REPLACE INTO subdomains 
                            (domain_id, subdomain, last_seen) 
                            VALUES (?, ?, CURRENT_TIMESTAMP)
                        ''', (domain_id, subdomain))
                        subdomains_added += 1
                    except sqlite3.Error as e:
                        print(f"Error adding subdomain {subdomain}: {e}")
            
            conn.commit()
        
        print(f"Added {subdomains_added} subdomains for domain {domain}")
    
    def add_subdomains_list(self, domain: str, subdomains: List[str]):
        """Add subdomains from list to database"""
        domain_id = self.get_or_create_domain(domain)
        subdomains_added = 0
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for subdomain in subdomains:
                if not subdomain.strip():
                    continue
                
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO subdomains 
                        (domain_id, subdomain, last_seen) 
                        VALUES (?, ?, CURRENT_TIMESTAMP)
                    ''', (domain_id, subdomain.strip()))
                    subdomains_added += 1
                except sqlite3.Error as e:
                    print(f"Error adding subdomain {subdomain}: {e}")
            
            conn.commit()
        
        print(f"Added {subdomains_added} subdomains for domain {domain}")
    
    def add_jsfiles(self, domain: str, jsfiles_json: str):
        """Add JS files from JSON to database"""
        domain_id = self.get_or_create_domain(domain)
        js_files_added = 0
        
        try:
            with open(jsfiles_json, 'r') as f:
                js_files_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error reading JS files JSON: {e}")
            return
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for js_file in js_files_data:
                if not isinstance(js_file, dict) or 'url' not in js_file:
                    continue
                
                url = js_file['url']
                size = js_file.get('size', 0)
                
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO js_files 
                        (domain_id, url, size, last_seen) 
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    ''', (domain_id, url, size))
                    js_files_added += 1
                except sqlite3.Error as e:
                    print(f"Error adding JS file {url}: {e}")
            
            conn.commit()
        
        print(f"Added {js_files_added} JS files for domain {domain}")
    
    def get_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """Get all subdomains for a domain"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT s.subdomain, s.is_live, s.first_seen, s.last_seen
                FROM subdomains s
                JOIN domains d ON s.domain_id = d.id
                WHERE d.domain = ?
                ORDER BY s.subdomain
            ''', (domain,))
            
            columns = ['subdomain', 'is_live', 'first_seen', 'last_seen']
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_jsfiles(self, domain: str) -> List[Dict[str, Any]]:
        """Get all JS files for a domain"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT j.url, j.size, j.first_seen, j.last_seen
                FROM js_files j
                JOIN domains d ON j.domain_id = d.id
                WHERE d.domain = ?
                ORDER BY j.url
            ''', (domain,))
            
            columns = ['url', 'size', 'first_seen', 'last_seen']
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_domains(self) -> List[Dict[str, Any]]:
        """Get all domains in database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT d.domain, d.created_at, d.last_scan, d.scan_count,
                       COUNT(DISTINCT s.id) as subdomain_count,
                       COUNT(DISTINCT j.id) as js_file_count
                FROM domains d
                LEFT JOIN subdomains s ON d.id = s.domain_id
                LEFT JOIN js_files j ON d.id = j.domain_id
                GROUP BY d.id
                ORDER BY d.last_scan DESC
            ''')
            
            columns = ['domain', 'created_at', 'last_scan', 'scan_count', 'subdomain_count', 'js_file_count']
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_domain_stats(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive stats for a domain"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get domain info
            cursor.execute('SELECT * FROM domains WHERE domain = ?', (domain,))
            domain_info = cursor.fetchone()
            
            if not domain_info:
                return {}
            
            # Get subdomain count
            cursor.execute('SELECT COUNT(*) FROM subdomains WHERE domain_id = ?', (domain_info[0],))
            subdomain_count = cursor.fetchone()[0]
            
            # Get live subdomain count
            cursor.execute('SELECT COUNT(*) FROM subdomains WHERE domain_id = ? AND is_live = 1', (domain_info[0],))
            live_subdomain_count = cursor.fetchone()[0]
            
            # Get JS file count
            cursor.execute('SELECT COUNT(*) FROM js_files WHERE domain_id = ?', (domain_info[0],))
            js_file_count = cursor.fetchone()[0]
            
            # Get scan history
            cursor.execute('''
                SELECT scan_type, scan_date, subdomains_found, js_files_found, vulnerabilities_found
                FROM scan_history 
                WHERE domain_id = ? 
                ORDER BY scan_date DESC 
                LIMIT 10
            ''', (domain_info[0],))
            
            scan_history = [dict(zip(['scan_type', 'scan_date', 'subdomains_found', 'js_files_found', 'vulnerabilities_found'], row)) 
                           for row in cursor.fetchall()]
            
            return {
                'domain': domain,
                'created_at': domain_info[2],
                'last_scan': domain_info[3],
                'scan_count': domain_info[4],
                'subdomain_count': subdomain_count,
                'live_subdomain_count': live_subdomain_count,
                'js_file_count': js_file_count,
                'recent_scans': scan_history
            }
    
    def update_subdomain_live_status(self, domain: str, subdomain: str, is_live: bool):
        """Update live status of a subdomain"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE subdomains 
                SET is_live = ?, last_seen = CURRENT_TIMESTAMP
                WHERE domain_id = (SELECT id FROM domains WHERE domain = ?) 
                AND subdomain = ?
            ''', (is_live, domain, subdomain))
            
            conn.commit()
    
    def add_scan_record(self, domain: str, scan_type: str, subdomains_found: int = 0, 
                       js_files_found: int = 0, vulnerabilities_found: int = 0):
        """Add scan record to history"""
        domain_id = self.get_or_create_domain(domain)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO scan_history 
                (domain_id, scan_type, subdomains_found, js_files_found, vulnerabilities_found)
                VALUES (?, ?, ?, ?, ?)
            ''', (domain_id, scan_type, subdomains_found, js_files_found, vulnerabilities_found))
            
            conn.commit()
    
    def search_subdomains(self, domain: str, pattern: str) -> List[Dict[str, Any]]:
        """Search subdomains by pattern"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT s.subdomain, s.is_live, s.first_seen, s.last_seen
                FROM subdomains s
                JOIN domains d ON s.domain_id = d.id
                WHERE d.domain = ? AND s.subdomain LIKE ?
                ORDER BY s.subdomain
            ''', (domain, f'%{pattern}%'))
            
            columns = ['subdomain', 'is_live', 'first_seen', 'last_seen']
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old data older than specified days"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Delete old scan history
            cursor.execute('''
                DELETE FROM scan_history 
                WHERE scan_date < datetime('now', '-{} days')
            '''.format(days))
            
            deleted_scans = cursor.rowcount
            
            # Delete domains with no subdomains and no recent activity
            cursor.execute('''
                DELETE FROM domains 
                WHERE id NOT IN (
                    SELECT DISTINCT domain_id FROM subdomains
                    UNION
                    SELECT DISTINCT domain_id FROM js_files
                ) AND last_scan < datetime('now', '-{} days')
            '''.format(days))
            
            deleted_domains = cursor.rowcount
            
            conn.commit()
            
            print(f"Cleaned up {deleted_scans} old scan records and {deleted_domains} inactive domains")

def main():
    """Command line interface for the database handler"""
    if len(sys.argv) < 2:
        print("Usage: python3 sqlite_db_handler.py <command> [args...]")
        print("\nCommands:")
        print("  add_subdomains_file <domain> <file>     - Add subdomains from file")
        print("  add_subdomains_list <domain> <sub1> <sub2> ... - Add subdomains from list")
        print("  add_jsfiles <domain> <json_file>        - Add JS files from JSON")
        print("  get_subdomains <domain>                 - Get all subdomains for domain")
        print("  get_jsfiles <domain>                    - Get all JS files for domain")
        print("  get_domains                             - Get all domains")
        print("  get_stats <domain>                      - Get domain statistics")
        print("  search_subdomains <domain> <pattern>    - Search subdomains by pattern")
        print("  cleanup <days>                          - Clean up old data")
        sys.exit(1)
    
    db = AutoARDatabase()
    command = sys.argv[1]
    
    try:
        if command == "add_subdomains_file":
            if len(sys.argv) < 4:
                print("Usage: add_subdomains_file <domain> <file>")
                sys.exit(1)
            db.add_subdomains_file(sys.argv[2], sys.argv[3])
        
        elif command == "add_subdomains_list":
            if len(sys.argv) < 3:
                print("Usage: add_subdomains_list <domain> <sub1> <sub2> ...")
                sys.exit(1)
            subdomains = sys.argv[3:]
            db.add_subdomains_list(sys.argv[2], subdomains)
        
        elif command == "add_jsfiles":
            if len(sys.argv) < 4:
                print("Usage: add_jsfiles <domain> <json_file>")
                sys.exit(1)
            db.add_jsfiles(sys.argv[2], sys.argv[3])
        
        elif command == "get_subdomains":
            if len(sys.argv) < 3:
                print("Usage: get_subdomains <domain>")
                sys.exit(1)
            subdomains = db.get_subdomains(sys.argv[2])
            print(json.dumps(subdomains, indent=2, default=str))
        
        elif command == "get_jsfiles":
            if len(sys.argv) < 3:
                print("Usage: get_jsfiles <domain>")
                sys.exit(1)
            js_files = db.get_jsfiles(sys.argv[2])
            print(json.dumps(js_files, indent=2, default=str))
        
        elif command == "get_domains":
            domains = db.get_domains()
            print(json.dumps(domains, indent=2, default=str))
        
        elif command == "get_stats":
            if len(sys.argv) < 3:
                print("Usage: get_stats <domain>")
                sys.exit(1)
            stats = db.get_domain_stats(sys.argv[2])
            print(json.dumps(stats, indent=2, default=str))
        
        elif command == "search_subdomains":
            if len(sys.argv) < 4:
                print("Usage: search_subdomains <domain> <pattern>")
                sys.exit(1)
            results = db.search_subdomains(sys.argv[2], sys.argv[3])
            print(json.dumps(results, indent=2, default=str))
        
        elif command == "cleanup":
            days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
            db.cleanup_old_data(days)
        
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
