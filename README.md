# Torvester

Email and credential harvester for darkweb OSINT.

## Disclaimer

This tool is for educational and security research purposes. Users are responsible for compliance with all applicable laws.

## Features

- Email, username, and password extraction
- Credential pair detection (email:password)
- Phone number extraction
- SQLite database with historical tracking
- Multi-threaded batch file processing
- Advanced token/key extraction
- Password pattern analysis
- Duplicate password detection
- Leak source identification
- CSV export

## Requirements

```bash
pip install requests beautifulsoup4
```

Tor must be running on `127.0.0.1:9050`.

## Installation

1. Install Tor:
   ```bash
   # Debian/Ubuntu
   sudo apt install tor
   sudo systemctl start tor
   
   # macOS
   brew install tor
   tor
   ```

2. Install dependencies:
   ```bash
   pip install requests beautifulsoup4
   ```

## Usage

```bash
torsocks python torvester.py
```

### Options

1. Extract from URL
2. Extract from file
3. Extract from text input
4. Batch extract from directory
5. Search database

## Output Structure

```
harvested_data/
├── emails.txt          # Email list
├── credentials.txt     # Email:password pairs
├── finding_*.json      # Individual findings
├── report_*.json       # Full report
├── export_*.csv        # CSV export
└── harvester.db        # SQLite database
```

## Database Schema

**emails table:**
- email, domain, first_seen, last_seen, source, breach_count

**credentials table:**
- email, password_hash, password_plain, source, timestamp

**findings table:**
- source, timestamp, data_type, value

## Analysis Features

**Domain Analysis:**
- Top domains by frequency
- Unique domain count

**Password Analysis:**
- Length distribution
- Character type usage (digits, special, upper, lower)
- Visual distribution graph

**Duplicate Detection:**
- Hash-based duplicate password identification
- Usage frequency tracking

**Leak Source Detection:**
- Collection identification
- Breach detection
- Paste site recognition
- Forum/market indicators

## Export

- JSON: Complete data with metadata
- TXT: Email and credential lists
- CSV: Tabular format (Type, Value, Source)

## About Project

Version : 1.0

License: MIT License - See LICENSE file

Developer: DR4CBOI

Contact: dr4cboi@protonmail.com
