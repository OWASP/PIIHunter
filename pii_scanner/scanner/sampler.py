"""
Data sampling strategies for PII scanning.

Implements intelligent sampling to minimize performance impact
while maximizing PII detection coverage.
"""

from typing import List, Dict, Any, Optional, Iterator
from dataclasses import dataclass
import random
import structlog
from psycopg2 import sql as pgsql

logger = structlog.get_logger(__name__)


@dataclass
class SampleResult:
    """Result of sampling a column."""

    schema_name: str
    table_name: str
    column_name: str
    total_rows: int
    sampled_rows: int
    sample_data: List[Dict[str, Any]]  # List of {pk: ..., value: ...}


class SamplingStrategy:
    """
    Base class for sampling strategies.
    """

    def __init__(self, db_connection):
        """
        Initialize sampling strategy.

        Args:
            db_connection: DatabaseConnection instance
        """
        self.db = db_connection

    def sample_column(
        self,
        schema_name: str,
        table_name: str,
        column_name: str,
        sample_size: int,
        pk_columns: Optional[List[str]] = None,
    ) -> SampleResult:
        """
        Sample data from a column.

        Args:
            schema_name: Schema name
            table_name: Table name
            column_name: Column to sample
            sample_size: Number of rows to sample
            pk_columns: Primary key column(s) for row identification

        Returns:
            SampleResult with sampled data
        """
        raise NotImplementedError


class RandomSampler(SamplingStrategy):
    """
    Random sampling strategy using TABLESAMPLE BERNOULLI.

    Fast for large tables, but may not be perfectly uniform.
    """

    def sample_column(
        self,
        schema_name: str,
        table_name: str,
        column_name: str,
        sample_size: int,
        pk_columns: Optional[List[str]] = None,
    ) -> SampleResult:
        """Sample using random sampling."""

        # Auto-detect primary key if not provided
        if not pk_columns:
            pk_columns = self._get_primary_key_columns(schema_name, table_name)
            if not pk_columns:
                pk_columns = ["ctid"]  # Fallback to PostgreSQL row identifier

        pk_identifiers = pgsql.SQL(", ").join(pgsql.Identifier(pk) for pk in pk_columns)
        col_identifier = pgsql.Identifier(column_name)
        schema_identifier = pgsql.Identifier(schema_name)
        table_identifier = pgsql.Identifier(table_name)

        # Get total row count
        count_sql = pgsql.SQL("SELECT COUNT(*) FROM {}.{}").format(
            schema_identifier, table_identifier
        )

        with self.db.get_cursor() as cur:
            cur.execute(count_sql)
            total_rows = cur.fetchone()[0]

        if total_rows == 0:
            logger.debug(
                "empty_table_skipped",
                table=f"{schema_name}.{table_name}",
            )
            return SampleResult(
                schema_name=schema_name,
                table_name=table_name,
                column_name=column_name,
                total_rows=0,
                sampled_rows=0,
                sample_data=[],
            )

        # For small tables, sample all rows
        if total_rows <= sample_size:
            sample_sql = pgsql.SQL(
                "SELECT {pk_cols}, {col} FROM {schema}.{table} WHERE {col} IS NOT NULL"
            ).format(
                pk_cols=pk_identifiers,
                col=col_identifier,
                schema=schema_identifier,
                table=table_identifier,
            )
        else:
            # Use random sampling
            # Calculate sample percentage
            sample_pct = min(100, (sample_size / total_rows) * 100 * 1.5)  # 1.5x overshoot

            sample_sql = pgsql.SQL(
                "SELECT {pk_cols}, {col} FROM {schema}.{table} "
                "TABLESAMPLE BERNOULLI ({pct}) WHERE {col} IS NOT NULL LIMIT {limit}"
            ).format(
                pk_cols=pk_identifiers,
                col=col_identifier,
                schema=schema_identifier,
                table=table_identifier,
                pct=pgsql.Literal(sample_pct),
                limit=pgsql.Literal(sample_size),
            )

        sample_data = []
        with self.db.get_cursor() as cur:
            cur.execute(sample_sql)
            for row in cur.fetchall():
                # Split PK and value
                pk_values = row[:-1]
                column_value = row[-1]

                # Build PK dict
                pk_dict = {}
                for i, pk_col in enumerate(pk_columns):
                    pk_dict[pk_col] = pk_values[i]

                sample_data.append({
                    "pk": pk_dict,
                    "value": column_value,
                })

        logger.debug(
            "column_sampled",
            column=f"{schema_name}.{table_name}.{column_name}",
            total_rows=total_rows,
            sampled_rows=len(sample_data),
        )

        return SampleResult(
            schema_name=schema_name,
            table_name=table_name,
            column_name=column_name,
            total_rows=total_rows,
            sampled_rows=len(sample_data),
            sample_data=sample_data,
        )

    def _get_primary_key_columns(
        self,
        schema_name: str,
        table_name: str,
    ) -> List[str]:
        """Get primary key column names for a table."""
        sql = """
            SELECT kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'PRIMARY KEY'
                AND tc.table_schema = %s
                AND tc.table_name = %s
            ORDER BY kcu.ordinal_position
        """

        with self.db.get_cursor() as cur:
            cur.execute(sql, (schema_name, table_name))
            return [row[0] for row in cur.fetchall()]


class StratifiedSampler(SamplingStrategy):
    """
    Stratified sampling to ensure diverse data coverage.

    Useful for columns with skewed distributions.
    """

    def sample_column(
        self,
        schema_name: str,
        table_name: str,
        column_name: str,
        sample_size: int,
        pk_columns: Optional[List[str]] = None,
    ) -> SampleResult:
        """
        Sample with stratification.

        Divides the table into strata and samples from each.
        """

        if not pk_columns:
            pk_columns = self._get_primary_key_columns(schema_name, table_name)
            if not pk_columns:
                pk_columns = ["ctid"]

        pk_identifiers = pgsql.SQL(", ").join(pgsql.Identifier(pk) for pk in pk_columns)
        col_identifier = pgsql.Identifier(column_name)
        schema_identifier = pgsql.Identifier(schema_name)
        table_identifier = pgsql.Identifier(table_name)

        # Get total row count
        count_sql = pgsql.SQL("SELECT COUNT(*) FROM {}.{}").format(
            schema_identifier, table_identifier
        )

        with self.db.get_cursor() as cur:
            cur.execute(count_sql)
            total_rows = cur.fetchone()[0]

        if total_rows == 0 or total_rows <= sample_size:
            # Fall back to simple sampling
            return RandomSampler(self.db).sample_column(
                schema_name, table_name, column_name, sample_size, pk_columns
            )

        # Stratify by dividing table into N strata
        num_strata = 10
        samples_per_stratum = sample_size // num_strata

        sample_data = []

        for i in range(num_strata):
            offset = (total_rows // num_strata) * i
            limit = samples_per_stratum

            stratum_sql = pgsql.SQL(
                "SELECT {pk_cols}, {col} FROM {schema}.{table} "
                "WHERE {col} IS NOT NULL ORDER BY {pk_cols} "
                "OFFSET {offset} LIMIT {limit}"
            ).format(
                pk_cols=pk_identifiers,
                col=col_identifier,
                schema=schema_identifier,
                table=table_identifier,
                offset=pgsql.Literal(offset),
                limit=pgsql.Literal(limit),
            )

            with self.db.get_cursor() as cur:
                cur.execute(stratum_sql)
                for row in cur.fetchall():
                    pk_values = row[:-1]
                    column_value = row[-1]

                    pk_dict = {}
                    for j, pk_col in enumerate(pk_columns):
                        pk_dict[pk_col] = pk_values[j]

                    sample_data.append({
                        "pk": pk_dict,
                        "value": column_value,
                    })

        logger.debug(
            "stratified_sampling_complete",
            column=f"{schema_name}.{table_name}.{column_name}",
            total_rows=total_rows,
            sampled_rows=len(sample_data),
            num_strata=num_strata,
        )

        return SampleResult(
            schema_name=schema_name,
            table_name=table_name,
            column_name=column_name,
            total_rows=total_rows,
            sampled_rows=len(sample_data),
            sample_data=sample_data,
        )

    def _get_primary_key_columns(
        self,
        schema_name: str,
        table_name: str,
    ) -> List[str]:
        """Get primary key column names for a table."""
        sql = """
            SELECT kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'PRIMARY KEY'
                AND tc.table_schema = %s
                AND tc.table_name = %s
            ORDER BY kcu.ordinal_position
        """

        with self.db.get_cursor() as cur:
            cur.execute(sql, (schema_name, table_name))
            return [row[0] for row in cur.fetchall()]


class StreamingSampler(SamplingStrategy):
    """
    Streaming sampler for full-table scans.

    Uses server-side cursors to avoid loading entire table into memory.
    Useful for high-risk columns that require exhaustive scanning.
    """

    def stream_column(
        self,
        schema_name: str,
        table_name: str,
        column_name: str,
        batch_size: int = 1000,
        pk_columns: Optional[List[str]] = None,
    ) -> Iterator[List[Dict[str, Any]]]:
        """
        Stream column data in batches.

        Args:
            schema_name: Schema name
            table_name: Table name
            column_name: Column to stream
            batch_size: Number of rows per batch
            pk_columns: Primary key column(s)

        Yields:
            Batches of sampled data
        """

        if not pk_columns:
            pk_columns = self._get_primary_key_columns(schema_name, table_name)
            if not pk_columns:
                pk_columns = ["ctid"]

        pk_identifiers = pgsql.SQL(", ").join(pgsql.Identifier(pk) for pk in pk_columns)

        stream_sql = pgsql.SQL(
            "SELECT {pk_cols}, {col} FROM {schema}.{table} WHERE {col} IS NOT NULL"
        ).format(
            pk_cols=pk_identifiers,
            col=pgsql.Identifier(column_name),
            schema=pgsql.Identifier(schema_name),
            table=pgsql.Identifier(table_name),
        )

        cursor_name = f"stream_{schema_name}_{table_name}_{column_name}"

        with self.db.get_server_cursor(name=cursor_name) as cur:
            cur.execute(stream_sql)

            while True:
                rows = cur.fetchmany(batch_size)
                if not rows:
                    break

                batch = []
                for row in rows:
                    pk_values = row[:-1]
                    column_value = row[-1]

                    pk_dict = {}
                    for i, pk_col in enumerate(pk_columns):
                        pk_dict[pk_col] = pk_values[i]

                    batch.append({
                        "pk": pk_dict,
                        "value": column_value,
                    })

                yield batch

        logger.debug(
            "streaming_complete",
            column=f"{schema_name}.{table_name}.{column_name}",
        )

    def _get_primary_key_columns(
        self,
        schema_name: str,
        table_name: str,
    ) -> List[str]:
        """Get primary key column names for a table."""
        sql = """
            SELECT kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'PRIMARY KEY'
                AND tc.table_schema = %s
                AND tc.table_name = %s
            ORDER BY kcu.ordinal_position
        """

        with self.db.get_cursor() as cur:
            cur.execute(sql, (schema_name, table_name))
            return [row[0] for row in cur.fetchall()]
