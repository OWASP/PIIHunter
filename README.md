# AI PII Scanner for PostgreSQL

> **An internal security tool for discovering Personally Identifiable Information (PII) in PostgreSQL databases**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-internal%20use%20only-red.svg)]()

## 🎯 Overview

The AI PII Scanner is a comprehensive, security-focused tool designed for Application Security and Privacy teams to discover and catalog PII across PostgreSQL databases. It uses a sophisticated layered detection approach combining:

- **🔍 Regex-based detection** - Deterministic patterns for email, phone, SSN, credit cards, etc.
- **🤖 NER/ML detection** - Microsoft Presidio or spaCy for entity recognition (names, locations, dates)
- **💬 Optional LLM classification** - Self-hosted models for ambiguous free-text analysis

### Key Features

✅ **Multi-layered PII Detection** - Combines regex, ML, and optional LLM for comprehensive coverage
✅ **Security-First Design** - Read-only access, no external API calls, minimal PII retention
✅ **Intelligent Sampling** - Analyzes representative data samples to minimize performance impact
✅ **Comprehensive Audit Trail** - Every scan logged with configuration, timestamps, and model versions
✅ **Detailed Reporting** - Column-level and table-level PII summaries with confidence scores
✅ **Privacy-Safe Logging** - Automatic PII redaction in all logs and stored samples

## 🚨 Security & Privacy

⚠️ **CRITICAL**: This tool is designed for **internal use only** within a secure, controlled environment.

| Security Control | Implementation |
|-----------------|----------------|
| **Data Exfiltration Prevention** | No third-party API calls; LLM endpoints must be self-hosted |
| **Least Privilege Access** | Read-only database role with no write access to application data |
| **PII Minimization** | Findings store only metadata and heavily redacted samples |
| **Audit Trail** | All scans logged with who/what/when/how details |
| **Secure Logging** | Structured logs with automatic PII field redaction |
| **Encrypted Transit** | SSL/TLS required for all database connections |

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [Detection Methods](#-detection-methods)
- [Database Schema](#-database-schema)
- [CLI Commands](#-cli-commands)
- [Examples](#-examples)
- [Troubleshooting](#-troubleshooting)
- [Advanced Topics](#-advanced-topics)
- [Contributing](#-contributing)

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- PostgreSQL database with read access
- 2GB RAM minimum
- 500MB disk space for dependencies

### Installation

```bash
# Clone the repository
cd AI_PIIScanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download spaCy NER model (~800MB)
python -m spacy download en_core_web_lg
```

### Initial Setup

**1. Create database role:**

```sql
-- As PostgreSQL superuser
CREATE ROLE pii_scanner_readonly WITH LOGIN PASSWORD 'your_secure_password';
GRANT CONNECT ON DATABASE your_database TO pii_scanner_readonly;
GRANT USAGE ON SCHEMA public, app_data TO pii_scanner_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public, app_data TO pii_scanner_readonly;
```

**2. Configure environment:**

```bash
cp .env.example .env
# Edit .env with your database credentials
```

**3. Initialize metadata schema:**

```bash
python -m pii_scanner.cli init-schema
```

### Run Your First Scan

```bash
# Discover candidate columns
python -m pii_scanner.cli discover

# Run PII detection scan
python -m pii_scanner.cli scan --sample-size 1000

# View results
python -m pii_scanner.cli report
```

## 📦 Installation

### Option 1: Development Install

```bash
cd AI_PIIScanner
pip install -e .
```

This makes the `pii-scanner` command available globally.

### Option 2: Production Install

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### Verify Installation

```bash
python -m pii_scanner.cli test-connection
```

Expected output:
```
Testing connection to localhost:5432/your_database...
✓ Connection successful!
```

## ⚙️ Configuration

Configuration is managed via environment variables in `.env`:

### Database Connection

```ini
DB_HOST=localhost
DB_PORT=5432
DB_NAME=your_database
DB_USER=pii_scanner_readonly
DB_PASSWORD=your_secure_password
DB_SSLMODE=require
```

### Scanning Options

```ini
# Schemas to scan (comma-separated)
SCHEMAS_TO_SCAN=public,app_data,customer_data

# Schemas to exclude (comma-separated)
SCHEMAS_TO_EXCLUDE=pg_catalog,information_schema,pg_toast

# Rows to sample per column
SAMPLE_SIZE=1000

# Batch size for streaming
BATCH_SIZE=500
```

### Detection Settings

```ini
# Minimum confidence threshold (0.0-1.0)
CONFIDENCE_THRESHOLD=0.5

# Enable/disable detection layers
ENABLE_REGEX_DETECTION=true
ENABLE_NER_DETECTION=true
ENABLE_LLM_DETECTION=false  # Only with self-hosted LLM
```

### LLM Configuration (Optional)

⚠️ **Only use with self-hosted endpoints**

```ini
LLM_ENDPOINT=http://your-internal-llm.company.local:8000/v1
LLM_API_KEY=your_private_key
LLM_MODEL=llama-2-7b
```

### Logging

```ini
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR
LOG_FORMAT=console  # console or json
```

## 🎮 Usage

### CLI Commands

#### Initialize Schema

Create the `security_pii` metadata schema:

```bash
python -m pii_scanner.cli init-schema
```

#### Discover Columns

Find candidate columns that may contain PII:

```bash
# Discover all columns
python -m pii_scanner.cli discover

# Discover specific schemas
python -m pii_scanner.cli discover --schemas public,customer_data

# Exclude schemas
python -m pii_scanner.cli discover --exclude test_data,staging
```

#### Run PII Scan

Execute a full PII detection scan:

```bash
# Default scan (uses .env settings)
python -m pii_scanner.cli scan

# Custom sample size
python -m pii_scanner.cli scan --sample-size 5000

# High-confidence columns only (faster)
python -m pii_scanner.cli scan --high-confidence-only

# Specific schemas
python -m pii_scanner.cli scan --schemas public --sample-size 2000
```

#### Generate Reports

View scan results:

```bash
# Latest scan report
python -m pii_scanner.cli report

# Specific scan run
python -m pii_scanner.cli report --run-id 5

# Limit number of findings
python -m pii_scanner.cli report --limit 100
```

#### Test Connection

Verify database connectivity:

```bash
python -m pii_scanner.cli test-connection
```

#### Drop Schema

⚠️ **DANGER**: Deletes all scan data

```bash
python -m pii_scanner.cli drop-schema --confirm
```

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                          CLI Layer                           │
│                      (pii_scanner/cli.py)                    │
│  Commands: init-schema, discover, scan, report               │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                     Scanning Engine                          │
│                 (pii_scanner/scanner/engine.py)              │
│  - Orchestrates discovery → sampling → detection             │
│  - Manages scan runs and metadata storage                    │
└─────────┬────────────────────┬────────────────┬─────────────┘
          │                    │                │
          ▼                    ▼                ▼
┌─────────────────┐  ┌─────────────────┐  ┌──────────────────┐
│ Column Discovery│  │  Data Sampler   │  │  PII Detectors   │
│                 │  │                 │  │                  │
│ - Metadata query│  │ - Random sample │  │ - Regex patterns │
│ - Rank columns  │  │ - Stratified    │  │ - Presidio NER   │
│ - Heuristics    │  │ - Streaming     │  │ - spaCy NER      │
│                 │  │                 │  │ - LLM (optional) │
└─────────────────┘  └─────────────────┘  └──────────────────┘
          │                    │                │
          └────────────────────┴────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Database Layer                            │
│  - Connection pooling (psycopg2)                             │
│  - Read-only enforcement                                     │
│  - Server-side cursors for streaming                         │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                 PostgreSQL Database                          │
│  Application Schemas (READ-ONLY) | security_pii (READ-WRITE)│
└─────────────────────────────────────────────────────────────┘
```

### Project Structure

```
AI_PIIScanner/
├── pii_scanner/
│   ├── __init__.py
│   ├── __main__.py           # Module entry point
│   ├── cli.py                # CLI commands
│   ├── config.py             # Configuration management
│   │
│   ├── database/
│   │   ├── connection.py     # Connection pooling
│   │   ├── schema.py         # Metadata schema DDL
│   │   └── discovery.py      # Column discovery logic
│   │
│   ├── detectors/
│   │   ├── base.py           # Abstract detector interfaces
│   │   ├── regex.py          # Regex-based detectors
│   │   ├── ner.py            # NER detectors (Presidio/spaCy)
│   │   └── llm.py            # LLM classifier
│   │
│   ├── scanner/
│   │   ├── engine.py         # Scan orchestration
│   │   └── sampler.py        # Sampling strategies
│   │
│   └── utils/
│       └── logging.py        # Structured logging
│
├── .env.example              # Example configuration
├── requirements.txt          # Python dependencies
├── setup.py                  # Package setup
├── README.md                 # This file
├── SETUP_GUIDE.md           # Detailed setup instructions
└── ARCHITECTURE.md          # Technical architecture docs
```

## 🔍 Detection Methods

### Layer 1: Regex-Based Detection

**Fast, deterministic pattern matching for well-defined PII types.**

| PII Type | Pattern | Validation | Confidence |
|----------|---------|------------|------------|
| Email | RFC-compliant regex | Format check | 0.95 |
| Phone | US + international formats | Format check | 0.95 |
| SSN | XXX-XX-XXXX | Area/group/serial validation | 0.95 |
| Credit Card | Visa, MC, Amex, Discover | Luhn algorithm | 0.95 |
| IP Address | IPv4 | Format check | 0.80 |
| URL | http/https | Format check | 0.70 |
| ZIP Code | US 5-digit + ZIP+4 | Format check | 0.70 |
| Crypto Wallet | Bitcoin, Ethereum | Format check | 0.85 |

### Layer 2: NER/ML Detection

**Machine learning-based entity recognition for variable patterns.**

**Microsoft Presidio** (preferred):
- Pre-trained recognizers for 50+ entity types
- Supports: PERSON, LOCATION, ORGANIZATION, DATE_TIME, MEDICAL_LICENSE, etc.
- Context-aware detection with confidence scores

**spaCy NER** (fallback):
- General-purpose named entity recognition
- Model: `en_core_web_lg` (~800MB)
- Entities: PERSON, GPE, LOC, ORG, DATE, TIME

### Layer 3: LLM Classification (Optional)

**Self-hosted LLM for ambiguous free-text columns.**

⚠️ **Security**: Only accepts self-hosted endpoints, rejects public APIs

- Use case: Notes, comments, descriptions with mixed/unstructured PII
- Prompt-based classification with JSON response
- Text truncation (max 500 chars) before processing
- Confidence threshold: 0.6+

### Detection Pipeline

1. All detectors run on the same text
2. Results merged and deduplicated
3. Overlapping entities resolved (highest confidence wins)
4. Final list with confidence scores returned

## 🗄️ Database Schema

The `security_pii` schema stores scan metadata and findings:

### Tables

**`scan_runs`** - Tracks each scan operation

```sql
id, started_at, completed_at, status, config, schemas_scanned,
presidio_version, spacy_model, total_tables_scanned,
total_columns_scanned, pii_findings_count, triggered_by
```

**`findings`** - Individual PII detections

```sql
id, run_id, table_schema, table_name, column_name, row_pk,
pii_type, confidence, detector_name, sample_redacted,
span_start, span_end
```

**`column_summary`** - Aggregated column-level statistics

```sql
id, table_schema, table_name, column_name, column_type,
last_scan_run_id, total_rows_scanned, rows_with_pii,
pii_percentage, pii_types_detected, classification,
is_nullable, is_unique, is_indexed, name_suggests_pii
```

### Views

**`high_confidence_pii`** - High-confidence findings (≥0.7)
**`column_pii_report`** - Column-level PII summary

## 📊 Examples

### Example 1: Initial Discovery

```bash
$ python -m pii_scanner.cli discover

Discovering columns in schemas: public, app_data
✓ Found 147 candidate columns

Top candidates by PII likelihood:

Score    Schema.Table.Column                           Type
------------------------------------------------------------------------
10.0     public.users.email                            varchar
10.0     public.users.phone_number                     varchar
9.0      public.customers.first_name                   text
9.0      public.customers.last_name                    text
8.0      public.addresses.street_address               text
7.0      public.orders.billing_zip                     varchar
```

### Example 2: Running a Scan

```bash
$ python -m pii_scanner.cli scan --sample-size 1000

============================================================
PII SCAN
============================================================
Schemas: public, app_data
Sample size: 1000 rows per column
Detectors: regex=True, ner=True, llm=False
============================================================

Starting scan...
✓ Scan completed! Run ID: 3

View results with: pii-scanner report --run-id 3
```

### Example 3: Viewing Results

```bash
$ python -m pii_scanner.cli report

============================================================
PII SCAN REPORT - Run #3
============================================================
Started: 2025-01-15 14:30:22
Completed: 2025-01-15 14:35:18
Status: completed
Tables scanned: 23
Columns scanned: 147
PII findings: 1,523
============================================================

Columns with PII:

Schema.Table.Column                    Class      PII %    Types
------------------------------------------------------------------------
public.users.email                     pii        98.5     EMAIL
public.users.phone_number              pii        87.2     PHONE_NUMBER
public.customers.ssn                   pii        95.3     SSN
public.orders.notes                    likely_pii 23.4     PERSON, LOCATION
```

### Example 4: Direct SQL Queries

```sql
-- High-confidence PII columns
SELECT
    table_schema,
    table_name,
    column_name,
    pii_percentage,
    pii_types_detected
FROM security_pii.column_summary
WHERE classification = 'pii'
ORDER BY pii_percentage DESC;

-- Detailed findings for a specific column
SELECT
    pii_type,
    confidence,
    COUNT(*) as occurrences,
    MAX(sample_redacted) as example
FROM security_pii.findings
WHERE table_name = 'users' AND column_name = 'email'
GROUP BY pii_type, confidence
ORDER BY occurrences DESC;
```

## 🔧 Troubleshooting

### Common Issues

**Connection refused**
```bash
# Verify DB_HOST and DB_PORT in .env
# Check firewall rules and PostgreSQL pg_hba.conf
python -m pii_scanner.cli test-connection
```

**Permission denied**
```sql
-- Grant required permissions
GRANT USAGE ON SCHEMA security_pii TO pii_scanner_readonly;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA security_pii TO pii_scanner_readonly;
```

**spaCy model not found**
```bash
python -m spacy download en_core_web_lg
```

**Out of memory**
```ini
# In .env, reduce resource usage
SAMPLE_SIZE=500
BATCH_SIZE=250
```

## 🎓 Advanced Topics

### Scheduled Scans

Use cron for periodic scans:

```bash
# Weekly scan every Sunday at 2 AM
0 2 * * 0 cd /path/to/AI_PIIScanner && ./venv/bin/python -m pii_scanner.cli scan >> /var/log/pii_scanner.log 2>&1
```

### CI/CD Integration

Run scans after database migrations:

```yaml
# .github/workflows/pii-scan.yml
- name: Run PII Scan
  run: |
    python -m pii_scanner.cli scan --schemas public --high-confidence-only
```

### Custom Detectors

Extend the system with custom detectors:

```python
from pii_scanner.detectors.base import PIIDetector, DetectedEntity, PIIType

class CustomDetector(PIIDetector):
    def detect(self, text: str) -> List[DetectedEntity]:
        # Your custom logic
        pass
```

## 📚 Documentation

- **[SETUP_GUIDE.md](SETUP_GUIDE.md)** - Detailed installation and configuration
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Technical architecture and design decisions

## 🤝 Contributing

This is an internal security tool. Contributions should be reviewed by the security team.

### Development Setup

```bash
git clone <repo>
cd AI_PIIScanner
python -m venv venv
source venv/bin/activate
pip install -e .
```

### Testing

```bash
# Run against test database
export DB_NAME=test_database
python -m pii_scanner.cli scan
```

## 📄 License

MIT License - Internal use only

## 🔒 Security Contact

For security concerns or questions, contact: `nayangoel@gmail.com`

---

**⚠️ Remember**: This tool processes sensitive data. Always follow your organization's security policies and data handling procedures.
