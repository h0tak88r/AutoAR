#!/usr/bin/env python3
import sys
import sqlite3
import os
import json
from typing import List, Dict

DB_PATH = os.path.join(os.path.dirname(__file__), 'autoar.sqlite')

# --- Schema ---
SCHEMA = [
    '''CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS subdomains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id INTEGER NOT NULL,
        subdomain TEXT NOT NULL,
        UNIQUE(domain_id, subdomain),
        FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
    )''',
    '''CREATE TABLE IF NOT EXISTS jsfiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        size INTEGER,
        last_seen TEXT,
        meta TEXT,
        UNIQUE(domain_id, url),
        FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
    )'''
]

# --- DB Helper ---
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    for stmt in SCHEMA:
        cur.execute(stmt)
    conn.commit()
    conn.close()

# --- CLI ---
def show_help():
    print('''\
SQLite DB Handler - Manage domains and subdomains

Usage:
    ./sqlite_db_handler.py <command> [arguments]

Commands:
    add_domain <domain>                     Add a single domain
    add_subdomain <domain> <subdomain>      Add a single subdomain to a domain
    add_subdomains_file <domain> <file>     Add multiple subdomains from a file
    list_domains                            List all domains
    list_domains_stats                      List all domains with their subdomain counts
    get_subdomains <domain>                 Get all subdomains for a domain
    get_all_subdomains                      Get all subdomains from database
    delete_domain <domain>                  Delete a domain and all its subdomains
    add_jsfiles <domain> <jsfile_list.json> Add or update JS files for a domain
    get_jsfiles <domain>                    Get all JS file records for a domain
    list_jsfiles <domain>                   List all JS files for a domain
    get_jsfile <domain> <url>               Get a specific JS file record for a domain
    update_jsfile <domain> <url> <meta>     Update a specific JS file record for a domain
    help                                    Show this help message
''')

# --- Domain Functions ---
def add_domain(domain: str):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute('INSERT OR IGNORE INTO domains(domain) VALUES (?)', (domain,))
        conn.commit()
        print(f"Added domain: {domain}")
    except Exception as e:
        print(f"Error adding domain: {e}")
    finally:
        conn.close()

def get_domain_id(domain: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT id FROM domains WHERE domain=?', (domain,))
    row = cur.fetchone()
    conn.close()
    return row['id'] if row else None

def add_subdomain(domain: str, subdomain: str):
    domain_id = get_domain_id(domain)
    if not domain_id:
        add_domain(domain)
        domain_id = get_domain_id(domain)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute('INSERT OR IGNORE INTO subdomains(domain_id, subdomain) VALUES (?, ?)', (domain_id, subdomain))
        conn.commit()
        print(f"Added subdomain: {subdomain} to domain: {domain}")
    except Exception as e:
        print(f"Error adding subdomain: {e}")
    finally:
        conn.close()

def add_subdomains_file(domain: str, file_path: str):
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return
    domain_id = get_domain_id(domain)
    if not domain_id:
        add_domain(domain)
        domain_id = get_domain_id(domain)
    conn = get_conn()
    cur = conn.cursor()
    count = 0
    with open(file_path, 'r') as f:
        for line in f:
            subdomain = line.strip()
            if subdomain:
                try:
                    cur.execute('INSERT OR IGNORE INTO subdomains(domain_id, subdomain) VALUES (?, ?)', (domain_id, subdomain))
                    count += 1
                except Exception as e:
                    print(f"Error adding subdomain: {subdomain}: {e}")
    conn.commit()
    conn.close()
    print(f"Added {count} subdomains to domain: {domain}")

def list_domains():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT domain FROM domains ORDER BY domain')
    for row in cur.fetchall():
        print(row['domain'])
    conn.close()

def list_domains_stats():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT d.domain, COUNT(s.id) as sub_count FROM domains d LEFT JOIN subdomains s ON d.id = s.domain_id GROUP BY d.id ORDER BY d.domain')
    print(f"{'Domain':<40} {'Subdomains':<10}")
    print('-' * 60)
    for row in cur.fetchall():
        print(f"{row['domain']:<40} {row['sub_count']:<10}")
    conn.close()

def get_subdomains(domain: str):
    domain_id = get_domain_id(domain)
    if not domain_id:
        print(f"Domain not found: {domain}")
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT subdomain FROM subdomains WHERE domain_id=? ORDER BY subdomain', (domain_id,))
    for row in cur.fetchall():
        print(row['subdomain'])
    conn.close()

def get_all_subdomains():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT d.domain, s.subdomain FROM subdomains s JOIN domains d ON s.domain_id = d.id ORDER BY d.domain, s.subdomain')
    for row in cur.fetchall():
        print(f"{row['subdomain']}")
    conn.close()

def delete_domain(domain: str):
    domain_id = get_domain_id(domain)
    if not domain_id:
        print(f"Domain not found: {domain}")
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('DELETE FROM domains WHERE id=?', (domain_id,))
    conn.commit()
    conn.close()
    print(f"Deleted domain: {domain} and all associated subdomains and jsfiles.")

# --- JSFiles Functions ---
def add_jsfiles(domain: str, jsfile_list: List[Dict]):
    domain_id = get_domain_id(domain)
    if not domain_id:
        add_domain(domain)
        domain_id = get_domain_id(domain)
    conn = get_conn()
    cur = conn.cursor()
    count = 0
    for jsf in jsfile_list:
        url = jsf.get('url')
        size = jsf.get('size')
        last_seen = jsf.get('last_seen')
        meta = json.dumps({k: v for k, v in jsf.items() if k not in ('url', 'size', 'last_seen')})
        try:
            cur.execute('INSERT OR REPLACE INTO jsfiles(domain_id, url, size, last_seen, meta) VALUES (?, ?, ?, ?, ?)',
                        (domain_id, url, size, last_seen, meta))
            count += 1
        except Exception as e:
            print(f"Error adding jsfile: {url}: {e}")
    conn.commit()
    conn.close()
    print(f"Added/updated {count} JS files for domain: {domain}")

def get_jsfiles(domain: str):
    domain_id = get_domain_id(domain)
    if not domain_id:
        print("[]")
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT url, size, last_seen, meta FROM jsfiles WHERE domain_id=?', (domain_id,))
    result = []
    for row in cur.fetchall():
        meta = json.loads(row['meta']) if row['meta'] else {}
        jsf = {'url': row['url'], 'size': row['size'], 'last_seen': row['last_seen']}
        jsf.update(meta)
        result.append(jsf)
    print(json.dumps(result, ensure_ascii=False))
    conn.close()

def list_jsfiles(domain: str):
    domain_id = get_domain_id(domain)
    if not domain_id:
        print(f"Domain not found: {domain}")
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT url, size, last_seen FROM jsfiles WHERE domain_id=?', (domain_id,))
    for row in cur.fetchall():
        print(row['url'], row['size'], row['last_seen'])
    conn.close()

def get_jsfile(domain: str, url: str):
    domain_id = get_domain_id(domain)
    if not domain_id:
        print("{}")
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT url, size, last_seen, meta FROM jsfiles WHERE domain_id=? AND url=?', (domain_id, url))
    row = cur.fetchone()
    if row:
        meta = json.loads(row['meta']) if row['meta'] else {}
        jsf = {'url': row['url'], 'size': row['size'], 'last_seen': row['last_seen']}
        jsf.update(meta)
        print(json.dumps(jsf, ensure_ascii=False))
    else:
        print("{}")
    conn.close()

def update_jsfile(domain: str, url: str, meta: dict):
    domain_id = get_domain_id(domain)
    if not domain_id:
        print(f"Domain not found: {domain}")
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT id FROM jsfiles WHERE domain_id=? AND url=?', (domain_id, url))
    row = cur.fetchone()
    if not row:
        print(f"JS file not found: {url}")
        conn.close()
        return
    # Update meta fields
    cur.execute('UPDATE jsfiles SET meta=? WHERE domain_id=? AND url=?', (json.dumps(meta), domain_id, url))
    conn.commit()
    conn.close()
    print(f"Updated JS file: {url}")

# --- Main ---
def main():
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help', 'help']:
        show_help()
        sys.exit(0)
    init_db()
    cmd = sys.argv[1]
    try:
        if cmd == "add_domain" and len(sys.argv) == 3:
            add_domain(sys.argv[2])
        elif cmd == "add_subdomain" and len(sys.argv) == 4:
            add_subdomain(sys.argv[2], sys.argv[3])
        elif cmd == "add_subdomains_file" and len(sys.argv) == 4:
            add_subdomains_file(sys.argv[2], sys.argv[3])
        elif cmd == "list_domains":
            list_domains()
        elif cmd == "list_domains_stats":
            list_domains_stats()
        elif cmd == "get_subdomains" and len(sys.argv) == 3:
            get_subdomains(sys.argv[2])
        elif cmd == "get_all_subdomains":
            get_all_subdomains()
        elif cmd == "delete_domain" and len(sys.argv) == 3:
            delete_domain(sys.argv[2])
        elif cmd == "add_jsfiles" and len(sys.argv) == 4:
            with open(sys.argv[3], 'r') as f:
                jsfiles = json.load(f)
            add_jsfiles(sys.argv[2], jsfiles)
        elif cmd == "get_jsfiles" and len(sys.argv) == 3:
            get_jsfiles(sys.argv[2])
        elif cmd == "list_jsfiles" and len(sys.argv) == 3:
            list_jsfiles(sys.argv[2])
        elif cmd == "get_jsfile" and len(sys.argv) == 4:
            get_jsfile(sys.argv[2], sys.argv[3])
        elif cmd == "update_jsfile" and len(sys.argv) == 5:
            meta = json.loads(sys.argv[4])
            update_jsfile(sys.argv[2], sys.argv[3], meta)
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