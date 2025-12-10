# PII Scanner - Setup Guide

Complete guide to installing, configuring, and running the PII Scanner.

---

## Prerequisites

- Python 3.8 or higher
- PostgreSQL database with appropriate permissions
- Network access to the target database
- Minimum 2GB RAM recommended
- 500MB disk space for dependencies and models

---

## Step 1: Install Python Dependencies

### Create Virtual Environment

```bash
cd AI_PIIScanner
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Install Required Packages

```bash
pip install -r requirements.txt
```

### Download spaCy Language Model

The NER detector requires a spaCy language model:

```bash
python -m spacy download en_core_web_lg
```

This downloads a ~800MB model with advanced NER capabilities.

---

## Step 2: Configure Database Access

### Create Read-Only Database Role

Connect to your PostgreSQL database as a superuser and create a dedicated read-only role:

```sql
-- Create read-only role
CREATE ROLE pii_scanner_readonly WITH LOGIN PASSWORD 'your_secure_password_here';

-- Grant connect permission
GRANT CONNECT ON DATABASE your_database_name TO pii_scanner_readonly;

-- Grant usage on schemas you want to scan
GRANT USAGE ON SCHEMA public, app_data TO pii_scanner_readonly;

-- Grant SELECT on all tables in those schemas
GRANT SELECT ON ALL TABLES IN SCHEMA public, app_data TO pii_scanner_readonly;

-- Grant SELECT on future tables (for schema evolution)
ALTER DEFAULT PRIVILEGES IN SCHEMA public, app_data
    GRANT SELECT ON TABLES TO pii_scanner_readonly;
```

### Grant Write Access to Metadata Schema

The scanner needs write access to the `security_pii` schema to store findings:

```sql
-- This will be created by the scanner, but we need to pre-grant permissions
-- Run this AFTER initializing the schema (step 3)
GRANT USAGE ON SCHEMA security_pii TO pii_scanner_readonly;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA security_pii TO pii_scanner_readonly;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA security_pii TO pii_scanner_readonly;
```

---

## Step 3: Configure Environment Variables

### Create .env File

Copy the example environment file:

```bash
cp .env.example .env
```

### Edit .env

Update the following required settings:

```ini
# Database Connection
DB_HOST=your-db-host.example.com
DB_PORT=5432
DB_NAME=your_database_name
DB_USER=pii_scanner_readonly
DB_PASSWORD=your_secure_password_here
DB_SSLMODE=require

# Schemas to Scan
SCHEMAS_TO_SCAN=public,app_data,customer_data
SCHEMAS_TO_EXCLUDE=pg_catalog,information_schema,pg_toast

# Scanning Configuration
SAMPLE_SIZE=1000
BATCH_SIZE=500

# Detection Settings
CONFIDENCE_THRESHOLD=0.5
ENABLE_REGEX_DETECTION=true
ENABLE_NER_DETECTION=true
ENABLE_LLM_DETECTION=false  # Only enable with self-hosted LLM

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=console  # Use 'json' for production
```

---

## Step 4: Initialize Metadata Schema

### Test Database Connection

First, verify connectivity:

```bash
python -m pii_scanner.cli test-connection
```

Expected output:
```
Testing connection to your-db-host.example.com:5432/your_database_name...
✓ Connection successful!
```

### Create Metadata Schema

Initialize the `security_pii` schema:

```bash
python -m pii_scanner.cli init-schema
```

Expected output:
```
Initializing security_pii schema...
✓ Schema initialized successfully!
  - security_pii.scan_runs
  - security_pii.findings
  - security_pii.column_summary
  - Views and indexes created
```

### Grant Permissions (if needed)

If using a separate admin account, grant write permissions:

```sql
GRANT USAGE ON SCHEMA security_pii TO pii_scanner_readonly;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA security_pii TO pii_scanner_readonly;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA security_pii TO pii_scanner_readonly;
```

---

## Step 5: Run Initial Discovery

### Discover Candidate Columns

Find columns that may contain PII:

```bash
python -m pii_scanner.cli discover
```

Expected output:
```
Discovering columns in schemas: public, app_data
Excluding schemas: pg_catalog, information_schema, pg_toast

✓ Found 147 candidate columns

Top candidates by PII likelihood:

Score    Schema.Table.Column                                          Type
------------------------------------------------------------------------------------------
10.0     public.users.email                                           varchar
10.0     public.users.phone_number                                    varchar
9.0      public.users.first_name                                      text
9.0      public.users.last_name                                       text
9.0      public.customers.ssn                                         varchar
8.0      public.addresses.street_address                              text
...
```

This helps you understand what the scanner will analyze.

---

## Step 6: Run First PII Scan

### Start a Full Scan

Run a scan with default settings (1000 rows sampled per column):

```bash
python -m pii_scanner.cli scan
```

### Scan Specific Schemas

To scan only certain schemas:

```bash
python -m pii_scanner.cli scan --schemas public,customer_data
```

### High-Confidence Columns Only

For faster initial scans, only scan high-likelihood columns:

```bash
python -m pii_scanner.cli scan --high-confidence-only
```

### Adjust Sample Size

To scan more thoroughly (slower but more accurate):

```bash
python -m pii_scanner.cli scan --sample-size 5000
```

Expected output:
```
============================================================
PII SCAN
============================================================
Schemas: public, app_data
Sample size: 1000 rows per column
High confidence only: False
Detectors: regex=True, ner=True, llm=False
============================================================

Starting scan...
✓ Scan completed! Run ID: 1

View results with: pii-scanner report --run-id 1
```

---

## Step 7: View Results

### Generate Report

View findings from the most recent scan:

```bash
python -m pii_scanner.cli report
```

### View Specific Run

```bash
python -m pii_scanner.cli report --run-id 1
```

Expected output:
```
============================================================
PII SCAN REPORT - Run #1
============================================================
Started: 2025-01-15 14:30:22
Completed: 2025-01-15 14:35:18
Status: completed
Tables scanned: 23
Columns scanned: 147
PII findings: 1,523
============================================================

Columns with PII (top 50):

Schema.Table.Column                                    Class        PII %    Types
----------------------------------------------------------------------------------------------------
public.users.email                                     pii          98.5     EMAIL
public.users.phone_number                              pii          87.2     PHONE_NUMBER
public.users.first_name                                pii          100.0    PERSON
public.customers.ssn                                   pii          95.3     SSN
public.addresses.street_address                        pii          100.0    ADDRESS
public.orders.notes                                    likely_pii   23.4     PERSON, LOCATION
...
```

---

## Step 8: Query Results Directly (Optional)

You can also query the metadata schema directly:

### View High-Confidence PII Columns

```sql
SELECT * FROM security_pii.high_confidence_pii
ORDER BY confidence DESC, occurrence_count DESC
LIMIT 20;
```

### Column-Level Summary

```sql
SELECT
    table_schema,
    table_name,
    column_name,
    classification,
    pii_percentage,
    pii_types_detected,
    last_scan_at
FROM security_pii.column_summary
WHERE classification = 'pii'
ORDER BY pii_percentage DESC;
```

### All Findings for a Specific Column

```sql
SELECT
    pii_type,
    confidence,
    detector_name,
    sample_redacted,
    COUNT(*) as occurrences
FROM security_pii.findings
WHERE table_schema = 'public'
  AND table_name = 'users'
  AND column_name = 'email'
GROUP BY pii_type, confidence, detector_name, sample_redacted
ORDER BY occurrences DESC;
```

---

## Advanced Configuration

### Enable LLM Detection (Self-Hosted Only)

⚠️ **WARNING**: Only use with self-hosted LLM endpoints. Never send real PII to public APIs.

```bash
# In .env
ENABLE_LLM_DETECTION=true
LLM_ENDPOINT=http://your-internal-llm.company.local:8000/v1
LLM_API_KEY=your_private_key
LLM_MODEL=llama-2-7b
```

### Scheduled Scans

Use cron or a scheduler to run periodic scans:

```bash
# crontab entry - run weekly on Sunday at 2 AM
0 2 * * 0 cd /path/to/AI_PIIScanner && ./venv/bin/python -m pii_scanner.cli scan --schemas public >> /var/log/pii_scanner.log 2>&1
```

### CI/CD Integration

Trigger scans after schema migrations:

```bash
# In your deployment pipeline
python -m pii_scanner.cli scan --schemas public --high-confidence-only
```

---

## Troubleshooting

### Connection Refused

**Error**: `connection to server at "host", port 5432 failed: Connection refused`

**Solution**:
- Verify `DB_HOST` and `DB_PORT` in `.env`
- Check firewall rules
- Ensure PostgreSQL is listening on the correct interface

### Permission Denied

**Error**: `permission denied for schema security_pii`

**Solution**:
```sql
GRANT USAGE ON SCHEMA security_pii TO pii_scanner_readonly;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA security_pii TO pii_scanner_readonly;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA security_pii TO pii_scanner_readonly;
```

### Presidio/spaCy Not Found

**Error**: `No module named 'presidio_analyzer'` or `Can't find model 'en_core_web_lg'`

**Solution**:
```bash
pip install presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_lg
```

### Out of Memory

**Error**: Process killed during scan

**Solution**:
- Reduce `SAMPLE_SIZE` in `.env` (e.g., 500 instead of 1000)
- Reduce `BATCH_SIZE` (e.g., 250 instead of 500)
- Use `--high-confidence-only` flag
- Scan schemas one at a time

---

## Security Best Practices

1. **Never commit `.env`** - Always in `.gitignore`
2. **Rotate credentials regularly** - Update `DB_PASSWORD` periodically
3. **Audit scan runs** - Review `security_pii.scan_runs` for unexpected activity
4. **Limit network access** - Run scanner in VPC/private network only
5. **Encrypt findings at rest** - Enable PostgreSQL encryption
6. **Monitor logs** - Watch for anomalies in scan behavior
7. **Read-only role** - Never grant write access to production schemas

---

## Next Steps

- Review findings and create data inventory
- Implement data masking/tokenization for identified PII columns
- Set up retention policies for scan metadata
- Integrate with your compliance/governance tools
- Create alerts for new PII columns in schema changes

For questions or issues, contact your security team.
