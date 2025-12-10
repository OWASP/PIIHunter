# PII Scanner - Architecture Documentation

This document describes the internal architecture and design decisions of the PII Scanner.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Component Architecture](#component-architecture)
3. [Data Flow](#data-flow)
4. [Database Schema](#database-schema)
5. [Detection Pipeline](#detection-pipeline)
6. [Security Model](#security-model)
7. [Performance Considerations](#performance-considerations)
8. [Extension Points](#extension-points)

---

## System Overview

The PII Scanner is a Python-based tool for discovering Personally Identifiable Information (PII) in PostgreSQL databases. It uses a layered detection approach combining:

- **Regex-based detectors** for deterministic patterns (email, phone, SSN, credit cards)
- **NER/ML detectors** using Presidio or spaCy for entity recognition (person names, locations)
- **Optional LLM classifiers** for ambiguous free-text (self-hosted only)

### Key Design Principles

1. **Security First**: No PII exfiltration to third parties
2. **Read-Only by Default**: Scanner uses least-privilege database roles
3. **Minimal Retention**: Findings store metadata and redacted samples only
4. **Auditability**: Every scan is tracked with configuration and timestamps
5. **Performance**: Sampling-based approach to minimize impact
6. **Explainability**: Multiple detectors with confidence scores

---

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                          CLI Layer                           │
│                      (pii_scanner/cli.py)                    │
│  Commands: init-schema, discover, scan, report               │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    Configuration Layer                       │
│                   (pii_scanner/config.py)                    │
│  - Environment variable loading (.env)                       │
│  - Pydantic-based validation                                 │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                     Scanning Engine                          │
│                 (pii_scanner/scanner/engine.py)              │
│  - Orchestrates discovery → sampling → detection             │
│  - Manages scan runs and metadata                            │
│  - Stores findings in security_pii schema                    │
└─────────┬────────────────────┬────────────────┬─────────────┘
          │                    │                │
          ▼                    ▼                ▼
┌─────────────────┐  ┌─────────────────┐  ┌──────────────────┐
│ Column Discovery│  │  Data Sampler   │  │  PII Detectors   │
│   (discovery.py)│  │  (sampler.py)   │  │  (detectors/*)   │
│                 │  │                 │  │                  │
│ - Query metadata│  │ - Random sample │  │ - Regex detector │
│ - Rank columns  │  │ - Stratified    │  │ - Presidio NER   │
│ - Heuristics    │  │ - Streaming     │  │ - spaCy NER      │
└─────────────────┘  └─────────────────┘  │ - LLM classifier │
                                           └──────────────────┘
          │                    │                │
          └────────────────────┴────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Database Layer                            │
│              (pii_scanner/database/connection.py)            │
│  - Connection pooling (psycopg2)                             │
│  - Context managers for safe resource handling               │
│  - Read-only mode enforcement                                │
│  - Server-side cursors for streaming                         │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                 PostgreSQL Database                          │
│  ┌────────────────────┐      ┌─────────────────────┐        │
│  │ Application Schemas│      │ security_pii Schema │        │
│  │ (public, app_data) │      │ - scan_runs         │        │
│  │ [READ-ONLY]        │      │ - findings          │        │
│  └────────────────────┘      │ - column_summary    │        │
│                              │ [READ-WRITE]        │        │
│                              └─────────────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### 1. Discovery Phase

```
User runs: pii-scanner discover

1. Config loads from .env
2. DatabaseConnection establishes pooled connections
3. ColumnDiscovery queries information_schema:
   - Find text-like columns (TEXT, VARCHAR, JSON, etc.)
   - Exclude system schemas
   - Query constraints/indexes
4. Scoring heuristics applied:
   - Column name patterns (email, phone, ssn, etc.)
   - Uniqueness + not-null = likely identifier
   - Index presence = important/searchable
5. Return ranked list of candidates
```

### 2. Scanning Phase

```
User runs: pii-scanner scan

1. ScanEngine.run_scan() starts:
   - Create scan_run record (status='running')
   - Discover columns (reuse discovery logic)

2. For each candidate column:
   a. Sample data:
      - RandomSampler pulls N rows (default 1000)
      - Uses TABLESAMPLE for large tables
      - Captures primary key for row identification

   b. Detect PII:
      - CompositeDetector coordinates all detectors
      - RegexDetector runs first (fast, deterministic)
      - NER detector (Presidio/spaCy) runs next
      - Optional LLM classifier for free-text
      - Entities deduplicated (highest confidence wins)

   c. Store findings:
      - Each detected entity → security_pii.findings
      - Store: table/column, PK, type, confidence, redacted sample

   d. Update column summary:
      - Calculate PII % (rows with PII / total sampled)
      - Classify: pii / likely_pii / non_pii / unknown
      - Store aggregated stats

3. Mark scan_run as completed
   - Update status, completion timestamp, totals
```

### 3. Reporting Phase

```
User runs: pii-scanner report

1. Query security_pii.scan_runs (latest or by ID)
2. Display run metadata (started, completed, totals)
3. Query security_pii.column_summary:
   - Filter by classification (pii, likely_pii)
   - Order by PII percentage
4. Format and display results
```

---

## Database Schema

The `security_pii` schema contains three main tables:

### scan_runs

Tracks each scan operation.

```sql
CREATE TABLE security_pii.scan_runs (
    id SERIAL PRIMARY KEY,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20),  -- running, completed, failed, cancelled

    -- Configuration snapshot
    config JSONB,
    schemas_scanned TEXT[],

    -- Model versions for reproducibility
    presidio_version VARCHAR(50),
    spacy_model VARCHAR(50),
    llm_model VARCHAR(100),

    -- Summary metrics
    total_tables_scanned INTEGER,
    total_columns_scanned INTEGER,
    total_rows_sampled BIGINT,
    pii_findings_count INTEGER,

    -- Audit
    triggered_by VARCHAR(100),
    error_message TEXT
);
```

### findings

Individual PII detections (row-level).

```sql
CREATE TABLE security_pii.findings (
    id BIGSERIAL PRIMARY KEY,
    run_id INTEGER REFERENCES scan_runs(id),

    -- Location
    table_schema VARCHAR(255),
    table_name VARCHAR(255),
    column_name VARCHAR(255),

    -- Row identifier (supports composite keys)
    row_pk JSONB,  -- e.g., {"id": 123}

    -- Detection metadata
    pii_type VARCHAR(100),  -- EMAIL, PHONE, SSN, etc.
    confidence DECIMAL(5,4),
    detector_name VARCHAR(50),  -- regex, presidio, llm

    -- Redacted sample
    sample_redacted TEXT,  -- e.g., "j***@***.com"
    span_start INTEGER,
    span_end INTEGER
);
```

### column_summary

Aggregated PII assessment per column.

```sql
CREATE TABLE security_pii.column_summary (
    id SERIAL PRIMARY KEY,

    table_schema VARCHAR(255),
    table_name VARCHAR(255),
    column_name VARCHAR(255),
    column_type VARCHAR(100),

    -- Scan metadata
    last_scan_run_id INTEGER REFERENCES scan_runs(id),
    last_scan_at TIMESTAMP WITH TIME ZONE,

    -- Statistics
    total_rows_scanned BIGINT,
    rows_with_pii INTEGER,
    pii_percentage DECIMAL(5,2),
    pii_types_detected TEXT[],

    -- Classification
    classification VARCHAR(20),  -- pii, non_pii, likely_pii, unknown
    classification_confidence DECIMAL(5,4),

    -- Column attributes (heuristics)
    is_nullable BOOLEAN,
    is_unique BOOLEAN,
    is_indexed BOOLEAN,
    is_primary_key BOOLEAN,
    has_foreign_key BOOLEAN,
    name_suggests_pii BOOLEAN,
    name_patterns_matched TEXT[],

    UNIQUE(table_schema, table_name, column_name)
);
```

---

## Detection Pipeline

### Layer 1: Regex Detectors (Fast, Deterministic)

**Purpose**: Catch well-defined patterns with high precision.

Patterns implemented:
- Email: `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}`
- Phone: US formats + international
- SSN: XXX-XX-XXXX (with validation)
- Credit Card: Visa, Mastercard, Amex, Discover (Luhn validated)
- IP Address: IPv4
- URL: http/https
- ZIP Code: US 5-digit and ZIP+4

**Confidence**: 0.95 (very high, false positives rare)

### Layer 2: NER Detectors (ML-Based)

**Purpose**: Detect entities that vary too much for regex (person names, locations).

**Option A: Microsoft Presidio** (preferred)
- Pre-trained entity recognizers
- Supports: PERSON, LOCATION, ORGANIZATION, DATE_TIME, etc.
- Confidence scores provided by model

**Option B: spaCy NER** (fallback)
- General-purpose NER
- en_core_web_lg model
- Entities: PERSON, GPE (geo-political), LOC, DATE

**Confidence**: 0.5-0.9 (model-dependent)

### Layer 3: LLM Classifier (Optional, Self-Hosted Only)

**Purpose**: Handle ambiguous free-text columns (notes, comments, descriptions).

**Safety Constraints**:
- Only accepts self-hosted endpoints (rejects public APIs)
- Truncates text to max 500 chars before sending
- Does not store full text in findings

**Prompt**:
```
Analyze the following text and identify any PII.
Respond with JSON: {"contains_pii": true/false, "entities": [...]}
```

**Confidence**: 0.6+ (lower than deterministic methods)

### Composite Detector Logic

1. All detectors run in parallel on the same text
2. Results merged into a single list
3. Overlapping entities resolved:
   - Keep highest confidence
   - If tied, keep longest span
4. Final deduplicated list returned

---

## Security Model

### Database Permissions

**Read-Only Role** (`pii_scanner_readonly`):
- SELECT on application schemas
- No INSERT, UPDATE, DELETE on application data
- No DDL permissions

**Write Access** (security_pii schema only):
- INSERT/UPDATE on scan_runs, findings, column_summary
- No access to application tables

### PII Protection

**Logs**:
- Structured logging via `structlog`
- Sensitive fields (password, api_key, etc.) auto-redacted
- Long strings truncated to prevent data leakage

**Findings Storage**:
- `sample_redacted`: Heavily masked (e.g., `j***@***.com`)
- `row_pk`: Only stores primary key, not full row
- No raw PII stored

**Network**:
- LLM endpoints validated (rejects public APIs)
- SSL enforced for database connections (`sslmode=require`)

---

## Performance Considerations

### Sampling Strategy

**Problem**: Full table scans are slow and resource-intensive.

**Solution**: Random sampling via `TABLESAMPLE BERNOULLI`.

- Sample N rows (default 1000) per column
- For tables < N rows, scan all rows
- For large tables, sample ~1-5% of data

**Trade-off**: May miss rare PII, but catches columns with >10% PII reliably.

### Connection Pooling

- Uses `psycopg2.pool.ThreadedConnectionPool`
- Min 1, Max 10 connections
- Reuses connections across queries

### Batch Processing

- Findings written in batches (not per-row)
- Server-side cursors for streaming (via `StreamingSampler`)
- LIMIT/OFFSET used to avoid memory exhaustion

### Parallelization (Future)

Not currently implemented, but extension point:
- Scan columns in parallel (ThreadPoolExecutor)
- Limit concurrency to avoid overwhelming DB

---

## Extension Points

### Adding New Detectors

1. Implement `PIIDetector` interface:
   ```python
   class CustomDetector(PIIDetector):
       def detect(self, text: str) -> List[DetectedEntity]:
           # Your logic here
           pass

       def supports_entity_type(self, entity_type: PIIType) -> bool:
           pass
   ```

2. Register in `ScanEngine._init_detectors()`:
   ```python
   detectors.append(CustomDetector())
   ```

### Adding New PII Types

1. Add to `PIIType` enum in `detectors/base.py`:
   ```python
   class PIIType(str, Enum):
       MY_CUSTOM_TYPE = "MY_CUSTOM_TYPE"
   ```

2. Implement detector logic in appropriate layer (regex/NER/LLM)

### Custom Sampling Strategies

1. Implement `SamplingStrategy` in `scanner/sampler.py`:
   ```python
   class CustomSampler(SamplingStrategy):
       def sample_column(...) -> SampleResult:
           # Your logic
   ```

2. Use in `ScanEngine`:
   ```python
   self.sampler = CustomSampler(db_connection)
   ```

### Integration with Compliance Tools

Export findings to external systems:

```python
# Query findings
findings = db.execute_query("""
    SELECT * FROM security_pii.column_summary
    WHERE classification = 'pii'
""")

# Convert to compliance format (e.g., DPIA, data map)
compliance_report = transform_to_compliance_format(findings)
```

---

## Performance Benchmarks

Typical performance on a moderate database:

- **Discovery**: ~5-10 seconds for 1000 columns
- **Scanning**: ~30-60 seconds per 100 columns (sample_size=1000)
- **Memory**: ~200-500 MB peak
- **Database load**: Minimal (read-only SELECTs, sampling used)

For large databases (10,000+ columns):
- Use `--high-confidence-only` for initial scans
- Reduce `sample_size` to 500
- Scan schemas incrementally

---

## Future Enhancements

1. **Parallel scanning**: Process multiple columns concurrently
2. **Incremental scans**: Only scan columns modified since last run
3. **ML-based column ranking**: Train model on historical findings
4. **Data lineage tracking**: Trace PII flow across tables (joins/FKs)
5. **Automated remediation**: Suggest masking/encryption for PII columns
6. **API/service mode**: FastAPI endpoint for on-demand scans
7. **Multi-database support**: MySQL, SQL Server, Oracle

---

## Conclusion

The PII Scanner balances security, performance, and accuracy through:

- Layered detection (regex → NER → LLM)
- Sampling-based approach
- Read-only database access
- Comprehensive audit trail

For questions or contributions, contact the security team.
