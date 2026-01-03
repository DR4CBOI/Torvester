#!/usr/bin/env python3

import os
import sys
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import json
import re
from collections import Counter
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import hashlib

BANNER = """
═══════════════════════════════════════
  _____                         _            
 |_   _|__  _ ____   _____  ___| |_ ___ _ __ 
   | |/ _ \| '__\ \ / / _ \/ __| __/ _ \ '__|
   | | (_) | |   \ V /  __/\__ \ ||  __/ |   
   |_|\___/|_|    \_/ \___||___/\__\___|_|   
                                                                                                      
═══════════════════════════════════════
Email & Credential Harvester

Developed by DR4CBOI
Github: https://github.com/DR4CBOI

Version: 1.0
═══════════════════════════════════════
"""

LEGAL_WARNING = """
═══════════════════════════════════════
⚠  LEGAL DISCLAIMER
═══════════════════════════════════════
This tool is for EDUCATIONAL and SECURITY 
RESEARCH purposes ONLY.

You are SOLELY responsible for compliance 
with all applicable laws.

Unauthorized access is ILLEGAL.
═══════════════════════════════════════
"""

class EmailHarvester:
    def __init__(self, proxy="socks5h://127.0.0.1:9050", use_database=True):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/115.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
        ]
        
        self.session = requests.Session()
        self.session.proxies = {'http': proxy, 'https': proxy}
        self.session.headers = {
            'User-Agent': self.user_agents[0]
        }
        self.emails = set()
        self.usernames = set()
        self.passwords = set()
        self.credentials = []
        self.phone_numbers = set()
        self.output_dir = "harvested_data"
        self.db_file = os.path.join(self.output_dir, "harvester.db")
        self.use_database = use_database
        self.db_conn = None
        self.lock = Lock()
        
        self.patterns = {
            'email': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
            'username': re.compile(r'\b(?:user(?:name)?|login|account):\s*([a-zA-Z0-9_-]{3,20})', re.IGNORECASE),
            'password': re.compile(r'\b(?:pass(?:word)?|pwd):\s*([^\s]{4,})', re.IGNORECASE),
            'credential_pair': re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^\s]{4,})'),
            'phone': re.compile(r'\+?[1-9]\d{1,14}'),
            'api_key': re.compile(r'\b[A-Za-z0-9]{32,}\b'),
            'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'ssh_key': re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
            'aws_key': re.compile(r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
            'aws_secret': re.compile(r'(?:aws_secret_access_key|aws_secret)\s*[=:]\s*([A-Za-z0-9/+=]{40})'),
            'jwt_token': re.compile(r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*'),
            'github_token': re.compile(r'ghp_[A-Za-z0-9]{36}'),
            'slack_token': re.compile(r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24}'),
            'discord_token': re.compile(r'[MNO][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}'),
            'stripe_key': re.compile(r'sk_live_[A-Za-z0-9]{24}')
        }
        
        self.ssh_keys = set()
        self.aws_keys = set()
        self.jwt_tokens = set()
        self.api_tokens = set()
        self.password_hashes = Counter()
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        if self.use_database:
            self.init_database()
    
    def init_database(self):
        try:
            self.db_conn = sqlite3.connect(self.db_file, check_same_thread=False)
            cursor = self.db_conn.cursor()
        
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                domain TEXT,
                first_seen TEXT,
                last_seen TEXT,
                source TEXT,
                breach_count INTEGER DEFAULT 0
            )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                password_hash TEXT,
                password_plain TEXT,
                source TEXT,
                timestamp TEXT
            )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                timestamp TEXT,
                data_type TEXT,
                value TEXT
            )
            ''')
            
            self.db_conn.commit()
        except sqlite3.Error as e:
            print(f"[DB ERROR] Failed to initialize database: {str(e)}")
            self.use_database = False
            self.db_conn = None
    
    def close_database(self):
        if self.db_conn:
            self.db_conn.close()
    
    def extract_from_url(self, url):
        if not url or not url.strip():
            print("[ERROR] Empty URL provided")
            return {}
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return self.extract_from_text(response.text, url)
        except requests.exceptions.Timeout:
            print(f"[ERROR] Timeout while accessing {url}")
            return {}
        except requests.exceptions.ConnectionError:
            print(f"[ERROR] Connection error for {url}")
            return {}
        except requests.exceptions.HTTPError as e:
            print(f"[ERROR] HTTP {e.response.status_code} for {url}")
            return {}
        except Exception as e:
            print(f"[ERROR] {url}: {str(e)}")
            return {}
    
    def extract_from_text(self, text, source=""):
        results = {}
        
        emails = self.patterns['email'].findall(text)
        if emails:
            results['emails'] = emails
            for email in emails:
                if email not in self.emails:
                    with self.lock:
                        self.emails.add(email)
                    self.save_email(email, source)
                    print(f"[EMAIL] {email}")
        
        usernames = self.patterns['username'].findall(text)
        if usernames:
            results['usernames'] = usernames
            for username in usernames:
                if username not in self.usernames:
                    with self.lock:
                        self.usernames.add(username)
                    self.save_finding('username', username, source)
                    print(f"[USER] {username}")
        
        passwords = self.patterns['password'].findall(text)
        if passwords:
            results['passwords'] = passwords
            for password in passwords:
                if password not in self.passwords:
                    with self.lock:
                        self.passwords.add(password)
                    self.save_finding('password', password, source)
                    print(f"[PASS] {password[:3]}***")
        
        cred_pairs = self.patterns['credential_pair'].findall(text)
        if cred_pairs:
            results['credentials'] = cred_pairs
            for email, password in cred_pairs:
                cred = {'email': email, 'password': password, 'source': source}
                if cred not in self.credentials:
                    with self.lock:
                        self.credentials.append(cred)
                    self.save_credential(email, password, source)
                    print(f"[CRED] {email}:{password[:3]}***")
        
        phones = self.patterns['phone'].findall(text)
        if phones:
            results['phones'] = phones
            for phone in phones:
                if phone not in self.phone_numbers:
                    with self.lock:
                        self.phone_numbers.add(phone)
                    self.save_finding('phone', phone, source)
                    print(f"[PHONE] {phone}")
        
        # SSH Keys
        ssh_keys = self.patterns['ssh_key'].findall(text)
        if ssh_keys:
            results['ssh_keys'] = ssh_keys
            for key in ssh_keys:
                key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
                if key_hash not in self.ssh_keys:
                    with self.lock:
                        self.ssh_keys.add(key_hash)
                    self.save_finding('ssh_key', key_hash, source)
                    print(f"[SSH KEY] {key_hash}...")
        
        # AWS Keys
        aws_keys = self.patterns['aws_key'].findall(text)
        if aws_keys:
            results['aws_keys'] = aws_keys
            for key in aws_keys:
                if key not in self.aws_keys:
                    with self.lock:
                        self.aws_keys.add(key)
                    self.save_finding('aws_key', key, source)
                    print(f"[AWS KEY] {key}")
        
        # JWT Tokens
        jwt_tokens = self.patterns['jwt_token'].findall(text)
        if jwt_tokens:
            results['jwt_tokens'] = jwt_tokens
            for token in jwt_tokens:
                token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
                if token_hash not in self.jwt_tokens:
                    with self.lock:
                        self.jwt_tokens.add(token_hash)
                    self.save_finding('jwt_token', token_hash, source)
                    print(f"[JWT] {token_hash}...")
        
        # API Tokens (GitHub, Slack, Discord, Stripe)
        for pattern_name in ['github_token', 'slack_token', 'discord_token', 'stripe_key']:
            tokens = self.patterns[pattern_name].findall(text)
            if tokens:
                for token in tokens:
                    token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
                    if token_hash not in self.api_tokens:
                        with self.lock:
                            self.api_tokens.add(token_hash)
                        self.save_finding(pattern_name, token_hash, source)
                        print(f"[{pattern_name.upper()}] {token_hash}...")
         
        # Track password hashes for duplicate detection
        for pwd in passwords:
            pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()
            self.password_hashes[pwd_hash] += 1
        
        # Detect leak source
        if results:
            leak_sources = self.detect_leak_source(text)
            results['leak_sources'] = leak_sources
            print(f"[SOURCE] Detected: {', '.join(leak_sources)}")
        
        if results and source:
            self.save_extraction(results, source)
        
        return results
    
    def extract_from_file(self, filepath):
        if not os.path.exists(filepath):
            print(f"[ERROR] File not found: {filepath}")
            return {}
        
        if not os.path.isfile(filepath):
            print(f"[ERROR] Not a file: {filepath}")
            return {}
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
            return self.extract_from_text(text, f"file://{filepath}")
        except IOError as e:
            print(f"[ERROR] Cannot read file {filepath}: {str(e)}")
            return {}
        except Exception as e:
            print(f"[ERROR] Unexpected error reading {filepath}: {str(e)}")
            return {}
    
    def batch_extract_files(self, directory, workers=5):
        files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        
        print(f"[BATCH] Processing {len(files)} files with {workers} workers...")
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.extract_from_file, f): f for f in files}
            
            from concurrent.futures import as_completed
            for future in as_completed(futures):
                filepath = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[ERROR] {filepath}: {str(e)}")
    
    def save_email(self, email, source):
        if not self.use_database:
            return
        
        cursor = self.db_conn.cursor()
        now = datetime.now().isoformat()
        domain = email.split('@')[1] if '@' in email else ''
        
        cursor.execute('''
            INSERT OR IGNORE INTO emails (email, domain, first_seen, last_seen, source)
            VALUES (?, ?, ?, ?, ?)
        ''', (email, domain, now, now, source))
        
        cursor.execute('''
            UPDATE emails SET last_seen = ?, source = ?
            WHERE email = ?
        ''', (now, source, email))
        
        self.db_conn.commit()
    
    def save_credential(self, email, password, source):
        if not self.use_database:
            return
        
        cursor = self.db_conn.cursor()
        now = datetime.now().isoformat()
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        
        cursor.execute('''
            INSERT INTO credentials (email, password_hash, password_plain, source, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (email, pwd_hash, password, source, now))
        
        self.db_conn.commit()
    
    def save_finding(self, data_type, value, source):
        if not self.use_database:
            return
        
        cursor = self.db_conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT INTO findings (source, timestamp, data_type, value)
            VALUES (?, ?, ?, ?)
        ''', (source, now, data_type, value))
        
        self.db_conn.commit()
    
    def save_extraction(self, data, source):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"finding_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        finding = {
            'timestamp': datetime.now().isoformat(),
            'source': source,
            'data': data
        }
        
        with open(filepath, 'w') as f:
            json.dump(finding, f, indent=2)
    
    def search_database(self, query, search_type='email'):
        if not self.use_database:
            print("[ERROR] Database not enabled")
            return []
        
        cursor = self.db_conn.cursor()
        
        if search_type == 'email':
            cursor.execute('''
                SELECT email, domain, first_seen, last_seen, source
                FROM emails
                WHERE email LIKE ?
            ''', (f'%{query}%',))
        elif search_type == 'domain':
            cursor.execute('''
                SELECT email, domain, first_seen, last_seen, source
                FROM emails
                WHERE domain LIKE ?
            ''', (f'%{query}%',))
        elif search_type == 'credential':
            cursor.execute('''
                SELECT email, password_plain, source, timestamp
                FROM credentials
                WHERE email LIKE ?
            ''', (f'%{query}%',))
        
        results = cursor.fetchall()
        
        print(f"\n[SEARCH] Found {len(results)} results for '{query}'")
        for i, row in enumerate(results[:10], 1):
            print(f"  {i}. {row}")
        
        return results
    
    def analyze_domains(self):
        domains = Counter()
        
        for email in self.emails:
            domain = email.split('@')[1] if '@' in email else None
            if domain:
                domains[domain] += 1
        
        print("\n" + "="*50)
        print("TOP DOMAINS")
        print("="*50)
        for domain, count in domains.most_common(10):
            print(f"{domain:30s} {count:>5d}")
        print("="*50)
        
        return domains
    
    def analyze_password_patterns(self):
        length_dist = Counter()
        has_digits = 0
        has_special = 0
        has_upper = 0
        has_lower = 0
        
        for pwd in self.passwords:
            length_dist[len(pwd)] += 1
            if any(c.isdigit() for c in pwd):
                has_digits += 1
            if any(not c.isalnum() for c in pwd):
                has_special += 1
            if any(c.isupper() for c in pwd):
                has_upper += 1
            if any(c.islower() for c in pwd):
                has_lower += 1
        
        total = len(self.passwords)
        if total > 0:
            print("\n" + "="*50)
            print("PASSWORD ANALYSIS")
            print("="*50)
            print(f"Total passwords: {total}")
            print(f"With digits:     {has_digits} ({has_digits/total*100:.1f}%)")
            print(f"With special:    {has_special} ({has_special/total*100:.1f}%)")
            print(f"With uppercase:  {has_upper} ({has_upper/total*100:.1f}%)")
            print(f"With lowercase:  {has_lower} ({has_lower/total*100:.1f}%)")
            print("\nLength distribution:")
            for length, count in sorted(length_dist.items()):
                bar = '█' * int(count/total*50)
                print(f"  {length:2d} chars: {count:>5d} {bar}")
            print("="*50)
    
    def generate_report(self):
        report = {
            'timestamp': datetime.now().isoformat(),
            'stats': {
                'total_emails': len(self.emails),
                'total_usernames': len(self.usernames),
                'total_passwords': len(self.passwords),
                'total_credentials': len(self.credentials),
                'total_phones': len(self.phone_numbers)
            },
            'emails': list(self.emails),
            'usernames': list(self.usernames),
            'credentials': self.credentials,
            'phones': list(self.phone_numbers)
        }
        
        if self.use_database:
            cursor = self.db_conn.cursor()
            cursor.execute('SELECT COUNT(DISTINCT domain) FROM emails')
            report['stats']['unique_domains'] = cursor.fetchone()[0]
        
        report_file = os.path.join(self.output_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        emails_file = os.path.join(self.output_dir, "emails.txt")
        with open(emails_file, 'w') as f:
            for email in sorted(self.emails):
                f.write(f"{email}\n")
        
        creds_file = os.path.join(self.output_dir, "credentials.txt")
        with open(creds_file, 'w') as f:
            for cred in self.credentials:
                f.write(f"{cred['email']}:{cred['password']}\n")
        
        print(f"\n[REPORT] Full report: {report_file}")
        print(f"[REPORT] Emails: {emails_file}")
        print(f"[REPORT] Credentials: {creds_file}")
    
    def analyze_password_hashes(self):
        print("\n" + "="*50)
        print("DUPLICATE PASSWORD ANALYSIS")
        print("="*50)
        
        if self.password_hashes:
            duplicates = {h: c for h, c in self.password_hashes.items() if c > 1}
            if duplicates:
                print(f"Found {len(duplicates)} passwords used multiple times:")
                for pwd_hash, count in sorted(duplicates.items(), key=lambda x: x[1], reverse=True)[:10]:
                    print(f"  {pwd_hash[:16]}... used {count} times")
            else:
                print("No duplicate passwords found")
        else:
            print("No passwords analyzed yet")
        print("="*50)
    
    def export_to_csv(self):
        import csv
        
        csv_file = os.path.join(self.output_dir, f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Value', 'Source'])
            
            for email in self.emails:
                writer.writerow(['Email', email, 'N/A'])
            
            for cred in self.credentials:
                writer.writerow(['Credential', f"{cred['email']}:{cred['password']}", cred['source']])
            
            for phone in self.phone_numbers:
                writer.writerow(['Phone', phone, 'N/A'])
        
        print(f"[EXPORT] CSV saved to {csv_file}")
        return csv_file
    
    def detect_leak_source(self, text):
        leak_indicators = {
            'collection': ['collection #', 'combo list', 'combolist'],
            'breach': ['breach', 'leaked', 'dump', 'database leak'],
            'paste': ['pastebin', 'paste.', 'ghostbin'],
            'forum': ['forum', 'thread', 'post #'],
            'market': ['market', 'shop', 'vendor']
        }
        
        text_lower = text.lower()
        sources = []
        
        for source_type, keywords in leak_indicators.items():
            if any(keyword in text_lower for keyword in keywords):
                sources.append(source_type)
        
        return sources if sources else ['unknown']
    
    def print_stats(self):
        print("\n" + "="*50)
        print("HARVESTER STATISTICS")
        print("="*50)
        print(f"Emails:      {len(self.emails)}")
        print(f"Usernames:   {len(self.usernames)}")
        print(f"Passwords:   {len(self.passwords)}")
        print(f"Credentials: {len(self.credentials)}")
        print(f"Phones:      {len(self.phone_numbers)}")
        if self.ssh_keys:
            print(f"SSH Keys:    {len(self.ssh_keys)}")
        if self.aws_keys:
            print(f"AWS Keys:    {len(self.aws_keys)}")
        if self.jwt_tokens:
            print(f"JWT Tokens:  {len(self.jwt_tokens)}")
        if self.api_tokens:
            print(f"API Tokens:  {len(self.api_tokens)}")
        print("="*50)

def main():
    print(BANNER)
    print(LEGAL_WARNING)
    input("\nPress ENTER to continue...")
    
    print("\n" + "="*50)
    print("Torvester")
    print("="*50)
    print("\nOptions:")
    print("1. Extract from URL")
    print("2. Extract from file")
    print("3. Extract from text input")
    print("4. Batch extract from directory")
    print("5. Search database")
    
    choice = input("\nSelect option (1-5): ").strip()
    
    use_db = input("Use database? (yes/no, default yes): ").strip().lower() or "yes"
    harvester = EmailHarvester(use_database=use_db in ['yes', 'y'])
    
    if choice == '1':
        url = input("Enter URL: ").strip()
        harvester.extract_from_url(url)
    
    elif choice == '2':
        filepath = input("Enter file path: ").strip()
        if os.path.exists(filepath):
            harvester.extract_from_file(filepath)
        else:
            print("[ERROR] File not found")
            sys.exit(1)
    
    elif choice == '3':
        print("Enter text (Ctrl+Z then Enter to finish on Windows, Ctrl+D on Linux/Mac):")
        text = sys.stdin.read()
        harvester.extract_from_text(text, "user_input")
    
    elif choice == '4':
        directory = input("Enter directory path: ").strip()
        if os.path.isdir(directory):
            workers = int(input("Number of workers (default 5): ").strip() or "5")
            harvester.batch_extract_files(directory, workers)
        else:
            print("[ERROR] Directory not found")
            sys.exit(1)
    
    elif choice == '5':
        if not harvester.use_database:
            print("[ERROR] Database not enabled")
            sys.exit(1)
        
        search_type = input("Search type (email/domain/credential): ").strip().lower()
        query = input("Search query: ").strip()
        harvester.search_database(query, search_type)
        harvester.close_database()
        sys.exit(0)
    
    else:
        print("[ERROR] Invalid choice")
        sys.exit(1)
    
    harvester.print_stats()
    harvester.analyze_domains()
    harvester.analyze_password_patterns()
    harvester.analyze_password_hashes()
    harvester.generate_report()
    
    # Ask for CSV export
    csv_export = input("\nExport to CSV? (yes/no): ").strip().lower()
    if csv_export in ['yes', 'y']:
        harvester.export_to_csv()
    
    if harvester.use_database:
        harvester.close_database()

if __name__ == "__main__":
    main()
