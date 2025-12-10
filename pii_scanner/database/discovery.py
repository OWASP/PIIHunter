"""
Schema and column discovery for PII scanning.

Queries PostgreSQL metadata to find candidate columns and ranks them
by likelihood of containing PII using heuristics.
"""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ColumnCandidate:
    """Represents a candidate column for PII scanning."""

    schema_name: str
    table_name: str
    column_name: str
    data_type: str
    is_nullable: bool
    is_unique: bool
    is_indexed: bool
    is_primary_key: bool
    has_foreign_key: bool
    max_length: Optional[int]
    pii_likelihood_score: float = 0.0
    name_patterns_matched: List[str] = None

    def __post_init__(self):
        if self.name_patterns_matched is None:
            self.name_patterns_matched = []

    @property
    def full_column_name(self) -> str:
        """Return fully qualified column name."""
        return f"{self.schema_name}.{self.table_name}.{self.column_name}"


class ColumnDiscovery:
    """
    Discovers and ranks columns that may contain PII.

    Uses information_schema and pg_catalog to find text-like columns
    and applies heuristics to rank them by PII likelihood.
    """

    # Text-like data types that may contain PII
    TEXT_TYPES = {
        "text",
        "varchar",
        "character varying",
        "char",
        "character",
        "citext",
        "bpchar",
    }

    # Semi-structured types that may contain PII
    SEMI_STRUCTURED_TYPES = {
        "json",
        "jsonb",
    }

    # Column name patterns strongly suggesting PII
    HIGH_CONFIDENCE_PATTERNS = {
        "email": 10.0,
        "mail": 8.0,
        "phone": 10.0,
        "mobile": 9.0,
        "ssn": 10.0,
        "social_security": 10.0,
        "first_name": 9.0,
        "last_name": 9.0,
        "firstname": 9.0,
        "lastname": 9.0,
        "full_name": 9.0,
        "name": 6.0,
        "address": 9.0,
        "street": 8.0,
        "city": 7.0,
        "zip": 7.0,
        "zipcode": 8.0,
        "postal": 7.0,
        "dob": 9.0,
        "birth_date": 9.0,
        "birthdate": 9.0,
        "password": 10.0,
        "credit_card": 10.0,
        "card_number": 10.0,
        "account": 7.0,
        "account_number": 8.0,
        "license": 8.0,
        "passport": 9.0,
        "ip_address": 7.0,
        "user_agent": 6.0,
    }

    # Column name patterns moderately suggesting PII
    MEDIUM_CONFIDENCE_PATTERNS = {
        "contact": 5.0,
        "personal": 5.0,
        "private": 5.0,
        "sensitive": 5.0,
        "info": 3.0,
        "detail": 3.0,
        "data": 2.0,
        "note": 4.0,
        "comment": 4.0,
        "description": 3.0,
    }

    # System schemas to always exclude
    SYSTEM_SCHEMAS = {
        "pg_catalog",
        "information_schema",
        "pg_toast",
        "pg_temp_1",
        "pg_toast_temp_1",
    }

    def __init__(self, db_connection):
        """
        Initialize column discovery.

        Args:
            db_connection: DatabaseConnection instance
        """
        self.db = db_connection

    def discover_columns(
        self,
        schemas: Optional[List[str]] = None,
        exclude_schemas: Optional[List[str]] = None,
        include_json: bool = True,
    ) -> List[ColumnCandidate]:
        """
        Discover all text-like columns in specified schemas.

        Args:
            schemas: List of schema names to scan (None = all non-system schemas)
            exclude_schemas: List of schema names to exclude
            include_json: Include JSON/JSONB columns

        Returns:
            List of ColumnCandidate objects, sorted by PII likelihood
        """
        logger.info(
            "discovering_columns",
            schemas=schemas,
            exclude_schemas=exclude_schemas,
            include_json=include_json,
        )

        # Build list of schemas to scan
        scan_schemas = self._get_schemas_to_scan(schemas, exclude_schemas)

        # Query for candidate columns
        candidates = self._query_candidate_columns(scan_schemas, include_json)

        # Enrich with constraint information
        candidates = self._enrich_with_constraints(candidates)

        # Score each candidate based on heuristics
        for candidate in candidates:
            candidate.pii_likelihood_score = self._score_column(candidate)

        # Sort by likelihood (highest first)
        candidates.sort(key=lambda c: c.pii_likelihood_score, reverse=True)

        logger.info(
            "column_discovery_complete",
            total_candidates=len(candidates),
            high_likelihood=len([c for c in candidates if c.pii_likelihood_score >= 7.0]),
            medium_likelihood=len([c for c in candidates if 4.0 <= c.pii_likelihood_score < 7.0]),
        )

        return candidates

    def _get_schemas_to_scan(
        self,
        schemas: Optional[List[str]],
        exclude_schemas: Optional[List[str]],
    ) -> Set[str]:
        """Determine which schemas to scan."""
        exclude = self.SYSTEM_SCHEMAS.copy()
        if exclude_schemas:
            exclude.update(exclude_schemas)

        if schemas:
            # User provided explicit list
            return set(schemas) - exclude

        # Get all user schemas
        sql = """
            SELECT schema_name
            FROM information_schema.schemata
            WHERE schema_name NOT IN %s
            ORDER BY schema_name
        """
        with self.db.get_cursor() as cur:
            cur.execute(sql, (tuple(exclude),))
            return {row[0] for row in cur.fetchall()}

    def _query_candidate_columns(
        self,
        schemas: Set[str],
        include_json: bool,
    ) -> List[ColumnCandidate]:
        """Query information_schema for text-like columns."""
        data_types = list(self.TEXT_TYPES)
        if include_json:
            data_types.extend(self.SEMI_STRUCTURED_TYPES)

        sql = """
            SELECT
                c.table_schema,
                c.table_name,
                c.column_name,
                c.data_type,
                c.is_nullable = 'YES' as is_nullable,
                c.character_maximum_length
            FROM information_schema.columns c
            WHERE
                c.table_schema = ANY(%s)
                AND c.data_type = ANY(%s)
            ORDER BY c.table_schema, c.table_name, c.ordinal_position
        """

        candidates = []
        with self.db.get_cursor() as cur:
            cur.execute(sql, (list(schemas), data_types))
            for row in cur.fetchall():
                candidates.append(
                    ColumnCandidate(
                        schema_name=row[0],
                        table_name=row[1],
                        column_name=row[2],
                        data_type=row[3],
                        is_nullable=row[4],
                        is_unique=False,  # Enriched later
                        is_indexed=False,  # Enriched later
                        is_primary_key=False,  # Enriched later
                        has_foreign_key=False,  # Enriched later
                        max_length=row[5],
                    )
                )

        return candidates

    def _enrich_with_constraints(
        self,
        candidates: List[ColumnCandidate],
    ) -> List[ColumnCandidate]:
        """
        Enrich candidates with constraint and index information.

        This helps identify columns that are likely to be unique identifiers.
        """
        # Build a map for quick lookup
        column_map = {}
        for c in candidates:
            key = (c.schema_name, c.table_name, c.column_name)
            column_map[key] = c

        # Query for primary keys
        pk_sql = """
            SELECT
                kcu.table_schema,
                kcu.table_name,
                kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'PRIMARY KEY'
        """

        with self.db.get_cursor() as cur:
            cur.execute(pk_sql)
            for row in cur.fetchall():
                key = (row[0], row[1], row[2])
                if key in column_map:
                    column_map[key].is_primary_key = True

        # Query for unique constraints
        unique_sql = """
            SELECT
                kcu.table_schema,
                kcu.table_name,
                kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'UNIQUE'
        """

        with self.db.get_cursor() as cur:
            cur.execute(unique_sql)
            for row in cur.fetchall():
                key = (row[0], row[1], row[2])
                if key in column_map:
                    column_map[key].is_unique = True

        # Query for foreign keys
        fk_sql = """
            SELECT
                kcu.table_schema,
                kcu.table_name,
                kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'FOREIGN KEY'
        """

        with self.db.get_cursor() as cur:
            cur.execute(fk_sql)
            for row in cur.fetchall():
                key = (row[0], row[1], row[2])
                if key in column_map:
                    column_map[key].has_foreign_key = True

        # Query for indexes (using pg_catalog for better info)
        index_sql = """
            SELECT DISTINCT
                n.nspname AS schema_name,
                t.relname AS table_name,
                a.attname AS column_name
            FROM pg_class t
            JOIN pg_namespace n ON n.oid = t.relnamespace
            JOIN pg_index ix ON t.oid = ix.indrelid
            JOIN pg_class i ON i.oid = ix.indexrelid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
            WHERE n.nspname = ANY(%s)
        """

        schemas = list({c.schema_name for c in candidates})
        with self.db.get_cursor() as cur:
            cur.execute(index_sql, (schemas,))
            for row in cur.fetchall():
                key = (row[0], row[1], row[2])
                if key in column_map:
                    column_map[key].is_indexed = True

        return candidates

    def _score_column(self, candidate: ColumnCandidate) -> float:
        """
        Score a column based on multiple heuristics.

        Returns:
            A score from 0.0 to 10.0 indicating PII likelihood
        """
        score = 0.0
        column_name_lower = candidate.column_name.lower()

        # Check high-confidence patterns
        for pattern, pattern_score in self.HIGH_CONFIDENCE_PATTERNS.items():
            if pattern in column_name_lower:
                score = max(score, pattern_score)
                candidate.name_patterns_matched.append(pattern)

        # Check medium-confidence patterns
        for pattern, pattern_score in self.MEDIUM_CONFIDENCE_PATTERNS.items():
            if pattern in column_name_lower:
                score = max(score, pattern_score)
                candidate.name_patterns_matched.append(pattern)

        # Boost score for unique + not null (likely identifier)
        if (candidate.is_unique or candidate.is_primary_key) and not candidate.is_nullable:
            score += 2.0

        # Boost for indexed columns (often searched/filtered = likely important)
        if candidate.is_indexed and not candidate.is_primary_key:
            score += 1.0

        # Reduce score for foreign keys (less likely to be direct PII)
        if candidate.has_foreign_key:
            score -= 1.0

        # JSON columns get a moderate boost (often contain nested PII)
        if candidate.data_type in self.SEMI_STRUCTURED_TYPES:
            score += 2.0

        # Clamp to 0-10 range
        return max(0.0, min(10.0, score))

    def get_column_stats(self, candidate: ColumnCandidate) -> Dict[str, Any]:
        """
        Get basic statistics for a column.

        Args:
            candidate: ColumnCandidate to analyze

        Returns:
            Dictionary with stats: total_rows, null_count, distinct_count
        """
        sql = f"""
            SELECT
                COUNT(*) as total_rows,
                COUNT(*) FILTER (WHERE {candidate.column_name} IS NULL) as null_count,
                COUNT(DISTINCT {candidate.column_name}) as distinct_count
            FROM {candidate.schema_name}.{candidate.table_name}
        """

        try:
            with self.db.get_cursor() as cur:
                cur.execute(sql)
                row = cur.fetchone()
                return {
                    "total_rows": row[0],
                    "null_count": row[1],
                    "distinct_count": row[2],
                }
        except Exception as e:
            logger.error(
                "failed_to_get_column_stats",
                column=candidate.full_column_name,
                error=str(e),
            )
            return {
                "total_rows": 0,
                "null_count": 0,
                "distinct_count": 0,
            }
