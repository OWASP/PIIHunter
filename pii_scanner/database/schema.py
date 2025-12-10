"""
Database schema definitions for PII scanning metadata.

This module contains SQL DDL for creating the security_pii schema and tables
that track scan runs, findings, and column-level summaries.
"""

# Schema creation SQL
CREATE_SCHEMA_SQL = """
-- Create dedicated schema for PII scanning metadata
CREATE SCHEMA IF NOT EXISTS security_pii;

-- Grant usage to the scanner role (adjust as needed)
-- GRANT USAGE ON SCHEMA security_pii TO pii_scanner_readonly;
-- GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA security_pii TO pii_scanner_readonly;
"""

# Scan runs table - tracks each scanning operation
CREATE_SCAN_RUNS_TABLE = """
CREATE TABLE IF NOT EXISTS security_pii.scan_runs (
    id SERIAL PRIMARY KEY,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL DEFAULT 'running',  -- running, completed, failed, cancelled

    -- Configuration snapshot
    config JSONB NOT NULL DEFAULT '{}',  -- scan config, thresholds, etc.
    schemas_scanned TEXT[] NOT NULL DEFAULT '{}',

    -- Model/version tracking
    presidio_version VARCHAR(50),
    spacy_model VARCHAR(50),
    llm_model VARCHAR(100),

    -- Summary statistics
    total_tables_scanned INTEGER DEFAULT 0,
    total_columns_scanned INTEGER DEFAULT 0,
    total_rows_sampled BIGINT DEFAULT 0,
    pii_findings_count INTEGER DEFAULT 0,

    -- Error tracking
    error_message TEXT,

    -- Audit
    triggered_by VARCHAR(100),  -- username, service account, or 'manual'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

CREATE INDEX idx_scan_runs_status ON security_pii.scan_runs(status);
CREATE INDEX idx_scan_runs_started_at ON security_pii.scan_runs(started_at DESC);
"""

# Findings table - individual PII detections
CREATE_FINDINGS_TABLE = """
CREATE TABLE IF NOT EXISTS security_pii.findings (
    id BIGSERIAL PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES security_pii.scan_runs(id) ON DELETE CASCADE,

    -- Location of PII
    table_schema VARCHAR(255) NOT NULL,
    table_name VARCHAR(255) NOT NULL,
    column_name VARCHAR(255) NOT NULL,

    -- Row identifier (supports composite keys via JSON)
    row_pk JSONB NOT NULL,  -- e.g., {"id": 123} or {"org_id": 5, "user_id": 42}

    -- Detection details
    pii_type VARCHAR(100) NOT NULL,  -- EMAIL, PHONE, SSN, PERSON, etc.
    confidence DECIMAL(5,4) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    detector_name VARCHAR(50) NOT NULL,  -- regex, presidio, llm

    -- Redacted sample (max 200 chars, heavily redacted)
    sample_redacted TEXT,

    -- Span information (for text position)
    span_start INTEGER,
    span_end INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

-- Indexes for efficient querying
CREATE INDEX idx_findings_run_id ON security_pii.findings(run_id);
CREATE INDEX idx_findings_table ON security_pii.findings(table_schema, table_name);
CREATE INDEX idx_findings_column ON security_pii.findings(table_schema, table_name, column_name);
CREATE INDEX idx_findings_pii_type ON security_pii.findings(pii_type);
CREATE INDEX idx_findings_confidence ON security_pii.findings(confidence DESC);
"""

# Column summary table - aggregated PII classification per column
CREATE_COLUMN_SUMMARY_TABLE = """
CREATE TABLE IF NOT EXISTS security_pii.column_summary (
    id SERIAL PRIMARY KEY,

    -- Column identity
    table_schema VARCHAR(255) NOT NULL,
    table_name VARCHAR(255) NOT NULL,
    column_name VARCHAR(255) NOT NULL,
    column_type VARCHAR(100) NOT NULL,

    -- Scanning metadata
    last_scan_run_id INTEGER REFERENCES security_pii.scan_runs(id),
    last_scan_at TIMESTAMP WITH TIME ZONE,

    -- Statistics from last scan
    total_rows_scanned BIGINT DEFAULT 0,
    rows_with_pii INTEGER DEFAULT 0,
    pii_percentage DECIMAL(5,2),  -- percentage of rows containing PII

    -- PII types found (array of distinct types)
    pii_types_detected TEXT[] DEFAULT '{}',

    -- Classification
    classification VARCHAR(20) NOT NULL DEFAULT 'unknown',  -- pii, non_pii, likely_pii, unknown
    classification_confidence DECIMAL(5,4),

    -- Column metadata signals
    is_nullable BOOLEAN,
    is_unique BOOLEAN,
    is_indexed BOOLEAN,
    is_primary_key BOOLEAN,
    has_foreign_key BOOLEAN,

    -- Name-based heuristics
    name_suggests_pii BOOLEAN DEFAULT FALSE,
    name_patterns_matched TEXT[],  -- e.g., ["email", "contact"]

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,

    -- Ensure one row per column
    UNIQUE(table_schema, table_name, column_name)
);

CREATE INDEX idx_column_summary_classification ON security_pii.column_summary(classification);
CREATE INDEX idx_column_summary_table ON security_pii.column_summary(table_schema, table_name);
CREATE INDEX idx_column_summary_last_scan ON security_pii.column_summary(last_scan_at DESC);
CREATE INDEX idx_column_summary_pii_percentage ON security_pii.column_summary(pii_percentage DESC NULLS LAST);
"""

# View for easy reporting
CREATE_VIEWS = """
-- View: High-confidence PII findings
CREATE OR REPLACE VIEW security_pii.high_confidence_pii AS
SELECT
    f.table_schema,
    f.table_name,
    f.column_name,
    f.pii_type,
    f.confidence,
    COUNT(*) as occurrence_count,
    MAX(f.created_at) as last_detected
FROM security_pii.findings f
WHERE f.confidence >= 0.7
GROUP BY f.table_schema, f.table_name, f.column_name, f.pii_type, f.confidence
ORDER BY f.confidence DESC, occurrence_count DESC;

-- View: Column-level PII summary
CREATE OR REPLACE VIEW security_pii.column_pii_report AS
SELECT
    cs.table_schema,
    cs.table_name,
    cs.column_name,
    cs.column_type,
    cs.classification,
    cs.pii_percentage,
    cs.pii_types_detected,
    cs.last_scan_at,
    sr.status as last_scan_status
FROM security_pii.column_summary cs
LEFT JOIN security_pii.scan_runs sr ON cs.last_scan_run_id = sr.id
WHERE cs.classification IN ('pii', 'likely_pii')
ORDER BY cs.pii_percentage DESC NULLS LAST;
"""

# Function to initialize the schema
INIT_SCHEMA_SQL = f"""
BEGIN;
{CREATE_SCHEMA_SQL}
{CREATE_SCAN_RUNS_TABLE}
{CREATE_FINDINGS_TABLE}
{CREATE_COLUMN_SUMMARY_TABLE}
{CREATE_VIEWS}
COMMIT;
"""


def get_init_schema_sql() -> str:
    """Return the complete SQL to initialize the security_pii schema."""
    return INIT_SCHEMA_SQL


def get_drop_schema_sql() -> str:
    """Return SQL to drop the security_pii schema (use with caution!)."""
    return """
    DROP SCHEMA IF EXISTS security_pii CASCADE;
    """
