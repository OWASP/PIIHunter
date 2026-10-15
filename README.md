# AI PII Scanner

> **An internal security tool for discovering Personally Identifiable Information (PII) in PostgreSQL databases and Jira projects**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

The AI PII Scanner is a comprehensive, security-focused tool designed for Application Security and Privacy teams to discover and catalog PII. It supports two scan targets:

- **PostgreSQL databases** — column-level PII discovery across your application schemas
- **Jira** — real-time or scheduled scanning of issues and comments for accidental PII exposure

Detection uses a three-layer pipeline:

- **Regex-based detection** — Deterministic patterns for email, phone, SSN, credit cards, etc.
- **NER/ML detection** — Microsoft Presidio or spaCy for entity recognition (names, locations, dates)
- **Optional LLM classification** — Self-hosted models for ambiguous free-text analysis

### Key Features

- **Multi-layered PII Detection** — Combines regex, ML, and optional LLM for comprehensive coverage
- **Jira Integration** — Scan new issues and comments via polling or real-time webhooks
- **Smart Exception Filters** — Suppress expected content: `@mentions` and company email addresses
- **Timestamped Reports** — Jira scan results auto-saved to a dated JSON or CSV file on every run
- **Security-First Design** — Read-only database access, no external API calls, minimal PII retention
- **Intelligent Sampling** — Analyzes representative data samples to minimize performance impact
- **Comprehensive Audit Trail** — Every scan logged with configuration, timestamps, and model versions
- **Privacy-Safe Logging** — Automatic PII redaction in all logs and stored samples

## Security & Privacy

**CRITICAL**: This tool is designed for **internal use only** within a secure, controlled environment.

| Security Control | Implementation |
|---|---|
| **Data Exfiltration Prevention** | No third-party API calls; LLM endpoints must be self-hosted |
| **Least Privilege Access** | Read-only database role with no write access to application data |
| **PII Minimization** | Findings store only metadata and heavily redacted samples |
| **Audit Trail** | All scans logged with who/what/when/how details |
| **Secure Logging** | Structured logs with automatic PII field redaction |
| **Encrypted Transit** | SSL/TLS required for all database connections |
| **Webhook Verification** | HMAC-SHA256 signature validation for incoming Jira events |

## Table of Contents

- [Installation — Database Schema Scan](#installation--database-schema-scan)
- [Installation — Jira Scan](#installation--jira-scan)
- [Configuration](#configuration)
- [Usage — Database Scanning](#usage--database-scanning)
- [Usage — Jira Integration](#usage--jira-integration)
- [Architecture](#architecture)
- [Detection Methods](#detection-methods)
- [Database Schema](#database-schema)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Advanced Topics](#advanced-topics)
- [Contributing](#contributing)

---

## Installation — Database Schema Scan

Use this if you want to scan a PostgreSQL database for PII across columns.

### Step 1 — Base install

```bash
# Clone the repository
cd PIIHunter

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download spaCy NER model (~800MB)
python -m spacy download en_core_web_lg
```

### Step 2 — Create a read-only database role

Run this as a PostgreSQL superuser:

```sql
CREATE ROLE pii_scanner_readonly WITH LOGIN PASSWORD 'your_secure_password';
GRANT CONNECT ON DATABASE your_database TO pii_scanner_readonly;
GRANT USAGE ON SCHEMA public, app_data TO pii_scanner_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public, app_data TO pii_scanner_readonly;
```

### Step 3 — Configure environment

```bash
cp .env.example .env
# Fill in DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
```

### Step 4 — Initialize metadata schema

Creates the `security_pii` schema where scan results are stored. Run once:

```bash
python -m pii_scanner.cli init-schema
```

### Step 5 — Run your first scan

```bash
# Preview candidate columns (no data read)
python -m pii_scanner.cli discover

# Run PII detection
python -m pii_scanner.cli scan --sample-size 1000

# View results
python -m pii_scanner.cli report
```

### Verify connectivity at any time

```bash
python -m pii_scanner.cli test-connection
```

---

## Installation — Jira Scan

Use this if you want to scan Jira issues and comments for accidental PII exposure.

The base install (Step 1 above) is required first. Database setup (Steps 2–4) is **not** required if you only want Jira scanning.

### Subsection A — REST API (Polling)

Polls Jira on demand for activity in the last N hours. No server needed.

**Step 1 — Base install** (if not done already)

```bash
cd PIIHunter
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

**Step 2 — Generate a Jira API token**

1. Go to `https://id.atlassian.com` → **Security** → **API tokens**
2. Click **Create API token**, give it a name, copy the token

**Step 3 — Configure environment**

```bash
cp .env.example .env
```

Edit `.env` and fill in your Jira details:

```ini
JIRA_URL=https://yourcompany.atlassian.net
JIRA_EMAIL=you@yourcompany.com
JIRA_API_TOKEN=your_api_token_here

# Optional — leave empty to scan all projects
# JIRA_PROJECT_KEYS=ENG,OPS,SUPPORT

# Emails from these domains will NOT be flagged as PII
COMPANY_EMAIL_DOMAINS=yourcompany.com
```

**Step 4 — Test the connection**

Verifies your credentials, lists accessible projects, and fetches a sample of recent issues:

```bash
python -m pii_scanner.cli jira test
```

Expected output:
```
Testing connection to https://yourcompany.atlassian.net...

  Auth          ✓  logged in as Jane Smith (jane@yourcompany.com)
  Projects      ✓  3 accessible: ENG, OPS, SUPPORT
  Project ENG   ✓  accessible

  Recent issues (no time filter):
    ENG-101  Fix login timeout on mobile
    ENG-100  Update password policy
```

If this fails, check your API token and that `JIRA_EMAIL` matches the account the token was generated for.

**Step 5 — Run a scan**

```bash
# Scan last 24 hours
python -m pii_scanner.cli jira scan

# Custom lookback window
python -m pii_scanner.cli jira scan --hours 48
```

---

### Subsection B — Webhook (Real-Time)

Starts an HTTP server that receives Jira events and scans them instantly as they arrive. Requires a publicly reachable endpoint.

**Step 1 — Base install + REST API setup** (complete Subsection A steps 1–4 first)

**Step 2 — Install webhook dependencies**

```bash
pip install fastapi uvicorn
```

**Step 3 — Add webhook config to `.env`**

```ini
# Secret used to verify requests genuinely come from Jira
JIRA_WEBHOOK_SECRET=your_webhook_secret
JIRA_WEBHOOK_PORT=8080
```

**Step 4 — Start the webhook server**

```bash
python -m pii_scanner.cli jira webhook

# Custom port
python -m pii_scanner.cli jira webhook --port 9090
```

**Step 5 — Register the webhook in Jira**

1. In Jira go to **Project Settings → Webhooks → Create webhook**
2. Set URL to `http://yourserver:8080/webhook`
3. Under **Events** select:
   - `Issue → created`
   - `Comment → created`
4. Set the secret to match `JIRA_WEBHOOK_SECRET` in your `.env`
5. Save

Jira will now POST to your server for every new issue and comment. The scanner processes each one immediately.

**Available endpoints:**

| Endpoint | Purpose |
|---|---|
| `POST /webhook` | Receives Jira events |
| `GET /health` | Confirms server is running |

> **Production note**: Do not expose uvicorn directly to the internet. See the [Production Webhook Setup](#production-webhook-setup) section under Advanced Topics.

---

## Configuration

All configuration is managed via environment variables in `.env`. Copy `.env.example` to get started.

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

> **Only use with self-hosted endpoints. Never point this at a public API.**

```ini
LLM_ENDPOINT=http://your-internal-llm.company.local:8000/v1
LLM_API_KEY=your_private_key
LLM_MODEL=llama-2-7b
```

### Jira Integration

```ini
# Jira connection
JIRA_URL=https://yourcompany.atlassian.net
JIRA_EMAIL=you@yourcompany.com
JIRA_API_TOKEN=your_jira_api_token   # generate at id.atlassian.com

# Projects to watch — leave empty to scan ALL accessible projects
# JIRA_PROJECT_KEYS=ENG,OPS,SUPPORT

# Emails from these domains are NOT flagged as PII (your internal addresses)
COMPANY_EMAIL_DOMAINS=yourcompany.com,internal.yourcompany.com

# Webhook server settings (only needed for real-time mode)
# JIRA_WEBHOOK_SECRET=your_webhook_secret
JIRA_WEBHOOK_PORT=8080
```

### Logging

```ini
LOG_LEVEL=INFO   # DEBUG, INFO, WARNING, ERROR
LOG_FORMAT=json  # json or console
```

---

## Usage — Database Scanning

### Initialize Schema

Create the `security_pii` metadata schema. Run once on first setup:

```bash
python -m pii_scanner.cli init-schema
```

### Discover Columns

Preview candidate columns ranked by PII likelihood — no data is read:

```bash
# Discover all columns
python -m pii_scanner.cli discover

# Specific schemas only
python -m pii_scanner.cli discover --schemas public,customer_data

# Exclude schemas
python -m pii_scanner.cli discover --exclude test_data,staging
```

### Run PII Scan

```bash
# Default scan (uses .env settings)
python -m pii_scanner.cli scan

# Custom sample size
python -m pii_scanner.cli scan --sample-size 5000

# High-confidence columns only (faster, skips ambiguous columns)
python -m pii_scanner.cli scan --high-confidence-only

# Specific schemas
python -m pii_scanner.cli scan --schemas public --sample-size 2000
```

### Generate Reports

```bash
# Latest scan report
python -m pii_scanner.cli report

# Specific scan run
python -m pii_scanner.cli report --run-id 5

# Limit number of findings shown
python -m pii_scanner.cli report --limit 100
```

### Other Commands

```bash
# Test database connectivity
python -m pii_scanner.cli test-connection

# Drop all scan data (DANGER — irreversible)
python -m pii_scanner.cli drop-schema --confirm
```

---

## Usage — Jira Integration

The Jira integration scans issue summaries, descriptions, and comments for accidental PII exposure using the same detection pipeline as the database scanner.

### Exception Rules

Two categories of content are automatically suppressed to avoid false positives:

| Rule | Example | Behaviour |
|---|---|---|
| `@mention` names | `@john.doe please review` | `PERSON` entity matching the mention is dropped |
| Company email addresses | `admin@yourcompany.com` | `EMAIL` entity matching configured domains is dropped |

Configure company domains in `.env`:
```ini
COMPANY_EMAIL_DOMAINS=yourcompany.com,internal.yourcompany.com
```

---

### Option 1 — Polling (Scheduled)

Fetches all new issues and comments from the last N hours on demand.

```bash
# Scan last 24 hours — report auto-saved as jira_pii_scan_YYYYMMDD_HHMMSS.json
python -m pii_scanner.cli jira scan

# Custom lookback window
python -m pii_scanner.cli jira scan --hours 48

# Save as CSV instead
python -m pii_scanner.cli jira scan --format csv

# Specify a custom output path
python -m pii_scanner.cli jira scan --output /reports/april_audit.json
```

**Use this when:**
- You want to run scans on a schedule (cron)
- You don't want to expose a public endpoint
- You want a one-off audit of recent activity

**Example cron — daily at 8 AM:**
```bash
0 8 * * * cd /path/to/PIIHunter && ./venv/bin/python -m pii_scanner.cli jira scan >> /var/log/pii_scanner_jira.log 2>&1
```

---

### Report Files

Every `jira scan` run automatically saves a report file. The filename includes the UTC date and time so each run produces a unique, traceable file.

**Default behaviour — JSON file in the current directory:**
```
jira_pii_scan_20260412_143022.json
```

**Supported formats:**

| Format | Flag | Use case |
|---|---|---|
| JSON | `--format json` (default) | Programmatic processing, archiving |
| CSV | `--format csv` | Spreadsheets, sharing with non-technical teams |

**Override the output path:**
```bash
# Save to a specific directory
python -m pii_scanner.cli jira scan --output /reports/april_audit.json

# Save as CSV to a specific path
python -m pii_scanner.cli jira scan --output /reports/april_audit.csv
```

The format is always inferred from the file extension — `.csv` produces CSV, everything else produces JSON.

---

### Option 2 — Webhook (Real-Time)

Starts an HTTP server that receives Jira events and scans them instantly as they arrive.

**Step 1 — Install webhook dependencies:**
```bash
pip install fastapi uvicorn
```

**Step 2 — Start the server:**
```bash
python -m pii_scanner.cli jira webhook
python -m pii_scanner.cli jira webhook --port 9090
```

**Step 3 — Configure Jira to send events:**

In Jira: `Project Settings → Webhooks → Create webhook`

- URL: `http://yourserver:8080/webhook`
- Events: `Issue Created`, `Comment Created`
- Secret: set `JIRA_WEBHOOK_SECRET` in `.env` to match

**Supported events:**

| Jira Event | What is scanned |
|---|---|
| `jira:issue_created` | Summary + description of new issue |
| `comment_created` | Body of new comment |

**Endpoints:**

| Endpoint | Purpose |
|---|---|
| `POST /webhook` | Receives Jira events |
| `GET /health` | Health check |

> **Production note**: Do not expose uvicorn directly to the internet. Put nginx or Caddy in front of it as a reverse proxy with TLS termination.

---

## Architecture

### System Components

```
┌──────────────────────────────────────────────────────────────┐
│                         CLI Layer                             │
│                     (pii_scanner/cli.py)                      │
│  DB commands: init-schema, discover, scan, report             │
│  Jira commands: jira scan, jira webhook                       │
└───────────────────────┬──────────────────────────────────────┘
                        │
          ┌─────────────┴─────────────┐
          ▼                           ▼
┌─────────────────────┐   ┌──────────────────────────────────┐
│   DB Scan Engine    │   │        Jira Integration          │
│  (scanner/engine)   │   │   (integrations/jira/)           │
│                     │   │                                  │
│ - Column discovery  │   │ - JiraClient  (API calls)        │
│ - Data sampling     │   │ - JiraFetcher (JQL + parsing)    │
│ - Findings storage  │   │ - JiraScanner (orchestration)    │
│                     │   │ - ExceptionFilter (@mention/     │
│                     │   │   company email suppression)     │
│                     │   │ - Webhook server (real-time)     │
└─────────┬───────────┘   └─────────────────┬────────────────┘
          │                                 │
          └──────────────┬──────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────┐
│                    PII Detectors                              │
│              (pii_scanner/detectors/)                         │
│                                                              │
│  RegexDetector    — email, phone, SSN, credit card, etc.     │
│  PresidioDetector — PERSON, LOCATION, DATE_TIME, etc.        │
│  SpacyNERDetector — fallback NER                             │
│  LLMClassifier    — optional, self-hosted only               │
│                                                              │
│  CompositeDetector — fans out to all, deduplicates results   │
└──────────────────────────────────────────────────────────────┘
```

### Project Structure

```
PIIHunter/
├── pii_scanner/
│   ├── __init__.py
│   ├── __main__.py               # Module entry point
│   ├── cli.py                    # All CLI commands
│   ├── config.py                 # Configuration (pydantic-settings)
│   │
│   ├── database/
│   │   ├── connection.py         # Connection pooling (psycopg2)
│   │   ├── schema.py             # Metadata schema DDL
│   │   └── discovery.py          # Column discovery + scoring
│   │
│   ├── detectors/
│   │   ├── base.py               # PIIDetector ABC + CompositeDetector
│   │   ├── regex.py              # Regex patterns + Luhn/SSN validation
│   │   ├── ner.py                # Presidio + spaCy detectors
│   │   └── llm.py                # Optional LLM classifier
│   │
│   ├── integrations/
│   │   └── jira/
│   │       ├── models.py         # JiraIssue, JiraComment, PIIFinding
│   │       ├── client.py         # Jira REST API client
│   │       ├── fetcher.py        # JQL queries + ADF text extraction
│   │       ├── filters.py        # @mention + company email exceptions
│   │       ├── scanner.py        # Scan orchestrator
│   │       ├── reporter.py       # JSON + CSV report file generation
│   │       └── webhook.py        # FastAPI real-time webhook server
│   │
│   ├── scanner/
│   │   ├── engine.py             # DB scan orchestration
│   │   └── sampler.py            # Sampling strategies
│   │
│   └── utils/
│       └── logging.py            # Structured logging setup
│
├── .env.example                  # Example configuration
├── requirements.txt              # Python dependencies
├── setup.py                      # Package setup
├── README.md                     # This file
├── SETUP_GUIDE.md                # Detailed setup instructions
└── ARCHITECTURE.md               # Technical architecture docs
```

---

## Detection Methods

### Layer 1: Regex-Based Detection

Fast, deterministic pattern matching for well-defined PII types.

| PII Type | Validation | Confidence |
|---|---|---|
| Email | Format check | 0.95 |
| Phone | US + international formats | 0.95 |
| SSN | Area/group/serial validation | 0.95 |
| Credit Card | Luhn algorithm | 0.95 |
| IP Address | Format check | 0.76 |
| URL | Format check | 0.67 |
| ZIP Code | US 5-digit + ZIP+4 | 0.67 |
| Crypto Wallet | Bitcoin + Ethereum format | 0.81 |
| Date of Birth | MM/DD/YYYY + ISO format | 0.76 |
| API Key | Long alphanumeric patterns | 0.95 |

### Layer 2: NER/ML Detection

Machine learning entity recognition for variable patterns.

**Microsoft Presidio** (preferred):
- Pre-trained recognizers for 50+ entity types
- Supports: PERSON, LOCATION, ORGANIZATION, DATE_TIME, MEDICAL_LICENSE, etc.
- Context-aware detection with per-entity confidence scores

**spaCy NER** (fallback):
- General-purpose NER model: `en_core_web_lg` (~800MB)
- Entities: PERSON, GPE, LOC, ORG, DATE, TIME

### Layer 3: LLM Classification (Optional)

Self-hosted LLM for ambiguous free-text columns (notes, comments, descriptions).

> **Security**: Only accepts self-hosted endpoints. Public API URLs are rejected.

- Text truncated to 500 chars before sending
- Confidence threshold: 0.6+
- Disabled by default (`ENABLE_LLM_DETECTION=false`)

### Detection Pipeline

1. All enabled detectors run on the same text
2. Results merged into a single list
3. Overlapping spans resolved — highest confidence wins
4. Final deduplicated list returned with confidence scores

---

## Database Schema

The `security_pii` schema (created by `init-schema`) stores all scan metadata:

### `scan_runs`

One row per scan operation.

```sql
id, started_at, completed_at, status, config,
schemas_scanned, presidio_version, spacy_model,
total_tables_scanned, total_columns_scanned,
pii_findings_count, triggered_by, error_message
```

### `findings`

One row per detected PII entity.

```sql
id, run_id, table_schema, table_name, column_name,
row_pk, pii_type, confidence, detector_name,
sample_redacted, span_start, span_end
```

### `column_summary`

Aggregated statistics per column, updated on each scan.

```sql
id, table_schema, table_name, column_name, column_type,
last_scan_run_id, total_rows_scanned, rows_with_pii,
pii_percentage, pii_types_detected, classification,
is_nullable, is_unique, is_indexed, name_suggests_pii
```

### Views

- **`high_confidence_pii`** — findings with confidence ≥ 0.7
- **`column_pii_report`** — column-level PII summary

---

## Examples

### Example 1: Database Column Discovery

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

### Example 2: Database PII Scan

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

### Example 3: Database Scan Report

```bash
$ python -m pii_scanner.cli report

============================================================
PII SCAN REPORT - Run #3
============================================================
Started:          2025-01-15 14:30:22
Completed:        2025-01-15 14:35:18
Status:           completed
Tables scanned:   23
Columns scanned:  147
PII findings:     1,523
============================================================

Columns with PII:

Schema.Table.Column                    Class      PII %    Types
------------------------------------------------------------------------
public.users.email                     pii        98.5     EMAIL
public.users.phone_number              pii        87.2     PHONE_NUMBER
public.customers.ssn                   pii        95.3     SSN
public.orders.notes                    likely_pii 23.4     PERSON, LOCATION
```

### Example 4: Jira Polling Scan

```bash
$ python -m pii_scanner.cli jira scan --hours 24

============================================================
JIRA PII SCAN
============================================================
Jira URL:         https://yourcompany.atlassian.net
Projects:         ALL
Lookback:         last 24 hours
Detectors:        regex=True, ner=True, llm=False
Ignoring domains: yourcompany.com
Output file:      jira_pii_scan_20260412_143022.json
============================================================

Scanning...

============================================================
RESULTS
============================================================
Items scanned:  42
Items with PII: 3
Total findings: 5
Filtered out:   2 (@mentions / company emails)
────────────────────────────────────────────────────────────

[ENG-456] issue_description
  PII Type             Confidence   Detector     Redacted
  ──────────────────────────────────────────────────────
  PHONE_NUMBER         0.95         regex        ***-***-4821
  PERSON               0.82         presidio     J*** S***

[SUPPORT-89] comment
  PII Type             Confidence   Detector     Redacted
  ──────────────────────────────────────────────────────
  SSN                  0.95         regex        ***-**-6723

✓ Report saved to: jira_pii_scan_20260412_143022.json
```

### Example 5: Jira Scan with CSV Output

```bash
$ python -m pii_scanner.cli jira scan --format csv --hours 48

Output file:      jira_pii_scan_20260412_143022.csv
...
✓ Report saved to: jira_pii_scan_20260412_143022.csv
```

### Example 6: Jira Scan with Custom Output Path

```bash
$ python -m pii_scanner.cli jira scan --output /reports/april_audit.json

Output file:      /reports/april_audit.json
...
✓ Report saved to: /reports/april_audit.json
```

### Example 7: Direct SQL Queries

```sql
-- High-confidence PII columns
SELECT table_schema, table_name, column_name,
       pii_percentage, pii_types_detected
FROM security_pii.column_summary
WHERE classification = 'pii'
ORDER BY pii_percentage DESC;

-- Detailed findings for a specific column
SELECT pii_type, confidence, COUNT(*) as occurrences,
       MAX(sample_redacted) as example
FROM security_pii.findings
WHERE table_name = 'users' AND column_name = 'email'
GROUP BY pii_type, confidence
ORDER BY occurrences DESC;
```

---

## Troubleshooting

### Database Issues

**Connection refused**
```bash
# Verify DB_HOST and DB_PORT in .env
python -m pii_scanner.cli test-connection
```

**Permission denied**
```sql
GRANT USAGE ON SCHEMA security_pii TO pii_scanner_readonly;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA security_pii TO pii_scanner_readonly;
```

**spaCy model not found**
```bash
python -m spacy download en_core_web_lg
```

**Out of memory**
```ini
# Reduce in .env
SAMPLE_SIZE=500
BATCH_SIZE=250
```

### Jira Issues

**Authentication failed**
```
✗ Jira authentication failed. Check email and API token.
```
Generate a new API token at `id.atlassian.com → Security → API tokens`.

**Missing configuration**
```
✗ Jira configuration missing. Set JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN in .env
```
All three values are required for any `jira` subcommand.

**Webhook not receiving events**
- Check the webhook URL is reachable from Jira's servers
- Verify the port is open in your firewall
- Check `JIRA_WEBHOOK_SECRET` matches what's configured in Jira
- Use `GET /health` to confirm the server is running

**fastapi/uvicorn not found**
```bash
pip install fastapi uvicorn
```
Only required for `jira webhook` mode.

---

## Advanced Topics

### Scheduled Jira Scans

```bash
# Daily at 8 AM — scan last 24 hours
0 8 * * * cd /path/to/PIIHunter && ./venv/bin/python -m pii_scanner.cli jira scan >> /var/log/pii_scanner_jira.log 2>&1

# Weekly database scan every Sunday at 2 AM
0 2 * * 0 cd /path/to/PIIHunter && ./venv/bin/python -m pii_scanner.cli scan >> /var/log/pii_scanner.log 2>&1
```

### Production Webhook Setup

Do not expose uvicorn directly. Use nginx as a reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name pii-scanner.internal.yourcompany.com;

    location /webhook {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Then run uvicorn bound to localhost only:
```bash
pii-scanner jira webhook --port 8080
# uvicorn binds to 0.0.0.0:8080 by default
# nginx handles TLS + external traffic
```

### CI/CD Integration

Run database scans after migrations:

```yaml
# .github/workflows/pii-scan.yml
- name: Run PII Scan
  run: |
    python -m pii_scanner.cli scan --schemas public --high-confidence-only
```

### Custom Detectors

Extend the system with your own detector:

```python
from pii_scanner.detectors.base import PIIDetector, DetectedEntity, PIIType

class CustomDetector(PIIDetector):
    def detect(self, text: str) -> List[DetectedEntity]:
        # Your custom logic
        pass

    def supports_entity_type(self, entity_type: PIIType) -> bool:
        pass
```

Register it in `ScanEngine._init_detectors()` or pass it directly to `CompositeDetector`.

---

## Documentation

- **[SETUP_GUIDE.md](SETUP_GUIDE.md)** — Detailed installation and configuration
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — Technical architecture and design decisions

---

## Contributing

This is an internal security tool. All contributions must be reviewed by the security team before merging.

```bash
git clone <repo>
cd PIIHunter
python -m venv venv
source venv/bin/activate
pip install -e .
```

---

## License

MIT License — Internal use only

## Security Contact

For security concerns or vulnerabilities, contact:
- `nayangoel@gmail.com`
- `nandan.gupta@gmail.com`

---

**This tool processes sensitive data. Always follow your organisation's security policies and data handling procedures.**
