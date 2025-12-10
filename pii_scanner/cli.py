"""
Command-line interface for the PII scanner.

Provides commands for initializing schema, discovering columns,
running scans, and generating reports.
"""

import click
import sys
from typing import Optional
import structlog

from .config import load_config, Config
from .database.connection import DatabaseConnection
from .database.schema import get_init_schema_sql, get_drop_schema_sql
from .database.discovery import ColumnDiscovery
from .scanner.engine import ScanEngine
from .utils.logging import configure_logging

logger = structlog.get_logger(__name__)


@click.group()
@click.option("--log-level", default=None, help="Log level (DEBUG, INFO, WARNING, ERROR)")
@click.option("--log-format", default=None, help="Log format (json, console)")
@click.pass_context
def cli(ctx, log_level: Optional[str], log_format: Optional[str]):
    """PII Scanner for PostgreSQL - Internal Security Tool"""
    ctx.ensure_object(dict)

    # Load configuration
    try:
        config = load_config()
        ctx.obj["config"] = config

        # Override log settings if provided
        if log_level:
            config.log_level = log_level
        if log_format:
            config.log_format = log_format

        # Configure logging
        configure_logging(config.log_level, config.log_format)

    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def init_schema(ctx):
    """Initialize the security_pii metadata schema."""
    config: Config = ctx.obj["config"]

    click.echo("Initializing security_pii schema...")

    try:
        db = DatabaseConnection(
            host=config.db_host,
            port=config.db_port,
            database=config.db_name,
            user=config.db_user,
            password=config.db_password,
            sslmode=config.db_sslmode,
        )

        # Execute schema initialization SQL
        init_sql = get_init_schema_sql()

        with db.get_connection() as conn:
            conn.set_session(readonly=False)
            with conn.cursor() as cur:
                cur.execute(init_sql)
                conn.commit()

        click.echo("✓ Schema initialized successfully!")
        click.echo("  - security_pii.scan_runs")
        click.echo("  - security_pii.findings")
        click.echo("  - security_pii.column_summary")
        click.echo("  - Views and indexes created")

        db.close()

    except Exception as e:
        logger.error("schema_init_failed", error=str(e))
        click.echo(f"✗ Schema initialization failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--confirm", is_flag=True, help="Confirm schema deletion")
@click.pass_context
def drop_schema(ctx, confirm: bool):
    """Drop the security_pii schema (DANGER: deletes all scan data)."""
    if not confirm:
        click.echo("This will DELETE all PII scan data!")
        click.echo("Use --confirm to proceed.")
        sys.exit(1)

    config: Config = ctx.obj["config"]

    click.echo("Dropping security_pii schema...")

    try:
        db = DatabaseConnection(
            host=config.db_host,
            port=config.db_port,
            database=config.db_name,
            user=config.db_user,
            password=config.db_password,
            sslmode=config.db_sslmode,
        )

        drop_sql = get_drop_schema_sql()

        with db.get_connection() as conn:
            conn.set_session(readonly=False)
            with conn.cursor() as cur:
                cur.execute(drop_sql)
                conn.commit()

        click.echo("✓ Schema dropped successfully")
        db.close()

    except Exception as e:
        logger.error("schema_drop_failed", error=str(e))
        click.echo(f"✗ Schema drop failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--schemas", help="Comma-separated schemas to scan")
@click.option("--exclude", help="Comma-separated schemas to exclude")
@click.pass_context
def discover(ctx, schemas: Optional[str], exclude: Optional[str]):
    """Discover candidate columns that may contain PII."""
    config: Config = ctx.obj["config"]

    schemas_list = schemas.split(",") if schemas else config.get_schemas_to_scan()
    exclude_list = exclude.split(",") if exclude else config.get_schemas_to_exclude()

    click.echo(f"Discovering columns in schemas: {', '.join(schemas_list)}")
    click.echo(f"Excluding schemas: {', '.join(exclude_list)}")

    try:
        db = DatabaseConnection(
            host=config.db_host,
            port=config.db_port,
            database=config.db_name,
            user=config.db_user,
            password=config.db_password,
            sslmode=config.db_sslmode,
        )

        discovery = ColumnDiscovery(db)
        candidates = discovery.discover_columns(
            schemas=schemas_list,
            exclude_schemas=exclude_list,
        )

        click.echo(f"\n✓ Found {len(candidates)} candidate columns\n")

        # Display top 20 by likelihood
        click.echo("Top candidates by PII likelihood:\n")
        click.echo(f"{'Score':<8} {'Schema.Table.Column':<60} {'Type':<15}")
        click.echo("-" * 90)

        for candidate in candidates[:20]:
            full_name = f"{candidate.schema_name}.{candidate.table_name}.{candidate.column_name}"
            click.echo(
                f"{candidate.pii_likelihood_score:<8.1f} "
                f"{full_name:<60} "
                f"{candidate.data_type:<15}"
            )

        if len(candidates) > 20:
            click.echo(f"\n... and {len(candidates) - 20} more")

        db.close()

    except Exception as e:
        logger.error("discovery_failed", error=str(e))
        click.echo(f"✗ Discovery failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--schemas", help="Comma-separated schemas to scan")
@click.option("--exclude", help="Comma-separated schemas to exclude")
@click.option("--sample-size", type=int, help="Number of rows to sample per column")
@click.option("--high-confidence-only", is_flag=True, help="Only scan high-confidence columns")
@click.pass_context
def scan(
    ctx,
    schemas: Optional[str],
    exclude: Optional[str],
    sample_size: Optional[int],
    high_confidence_only: bool,
):
    """Run a PII scan on the database."""
    config: Config = ctx.obj["config"]

    schemas_list = schemas.split(",") if schemas else config.get_schemas_to_scan()
    exclude_list = exclude.split(",") if exclude else config.get_schemas_to_exclude()
    sample_size = sample_size or config.sample_size

    click.echo("=" * 60)
    click.echo("PII SCAN")
    click.echo("=" * 60)
    click.echo(f"Schemas: {', '.join(schemas_list)}")
    click.echo(f"Sample size: {sample_size} rows per column")
    click.echo(f"High confidence only: {high_confidence_only}")
    click.echo(f"Detectors: regex={config.enable_regex_detection}, "
               f"ner={config.enable_ner_detection}, llm={config.enable_llm_detection}")
    click.echo("=" * 60)
    click.echo()

    try:
        db = DatabaseConnection(
            host=config.db_host,
            port=config.db_port,
            database=config.db_name,
            user=config.db_user,
            password=config.db_password,
            sslmode=config.db_sslmode,
        )

        # Create scan engine
        engine = ScanEngine(db, config.to_dict())

        # Run scan
        click.echo("Starting scan...")
        run_id = engine.run_scan(
            schemas=schemas_list,
            exclude_schemas=exclude_list,
            sample_size=sample_size,
            high_confidence_only=high_confidence_only,
        )

        click.echo(f"\n✓ Scan completed! Run ID: {run_id}")
        click.echo(f"\nView results with: pii-scanner report --run-id {run_id}")

        db.close()

    except Exception as e:
        logger.error("scan_failed", error=str(e))
        click.echo(f"\n✗ Scan failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--run-id", type=int, help="Specific run ID to report on")
@click.option("--limit", type=int, default=50, help="Number of findings to show")
@click.pass_context
def report(ctx, run_id: Optional[int], limit: int):
    """Generate a report of PII findings."""
    config: Config = ctx.obj["config"]

    try:
        db = DatabaseConnection(
            host=config.db_host,
            port=config.db_port,
            database=config.db_name,
            user=config.db_user,
            password=config.db_password,
            sslmode=config.db_sslmode,
        )

        # Get latest run if not specified
        if not run_id:
            sql = "SELECT id FROM security_pii.scan_runs ORDER BY started_at DESC LIMIT 1"
            with db.get_cursor() as cur:
                cur.execute(sql)
                row = cur.fetchone()
                if row:
                    run_id = row[0]
                else:
                    click.echo("No scan runs found. Run a scan first.")
                    sys.exit(1)

        # Get run details
        sql = """
            SELECT
                id,
                started_at,
                completed_at,
                status,
                total_tables_scanned,
                total_columns_scanned,
                pii_findings_count
            FROM security_pii.scan_runs
            WHERE id = %s
        """

        with db.get_cursor() as cur:
            cur.execute(sql, (run_id,))
            run = cur.fetchone()

        if not run:
            click.echo(f"Run ID {run_id} not found")
            sys.exit(1)

        click.echo("=" * 60)
        click.echo(f"PII SCAN REPORT - Run #{run[0]}")
        click.echo("=" * 60)
        click.echo(f"Started: {run[1]}")
        click.echo(f"Completed: {run[2]}")
        click.echo(f"Status: {run[3]}")
        click.echo(f"Tables scanned: {run[4]}")
        click.echo(f"Columns scanned: {run[5]}")
        click.echo(f"PII findings: {run[6]}")
        click.echo("=" * 60)
        click.echo()

        # Get column-level summary
        sql = """
            SELECT
                table_schema,
                table_name,
                column_name,
                classification,
                pii_percentage,
                pii_types_detected
            FROM security_pii.column_summary
            WHERE last_scan_run_id = %s
                AND classification IN ('pii', 'likely_pii')
            ORDER BY pii_percentage DESC
            LIMIT %s
        """

        with db.get_cursor() as cur:
            cur.execute(sql, (run_id, limit))
            columns = cur.fetchall()

        if columns:
            click.echo(f"Columns with PII (top {limit}):\n")
            click.echo(f"{'Schema.Table.Column':<50} {'Class':<12} {'PII %':<8} {'Types'}")
            click.echo("-" * 100)

            for col in columns:
                full_name = f"{col[0]}.{col[1]}.{col[2]}"
                pii_types = ", ".join(col[5][:3])  # Show first 3 types
                if len(col[5]) > 3:
                    pii_types += f" +{len(col[5]) - 3}"

                click.echo(
                    f"{full_name:<50} "
                    f"{col[3]:<12} "
                    f"{col[4]:<8.1f} "
                    f"{pii_types}"
                )

        db.close()

    except Exception as e:
        logger.error("report_failed", error=str(e))
        click.echo(f"✗ Report generation failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def test_connection(ctx):
    """Test database connection."""
    config: Config = ctx.obj["config"]

    click.echo(f"Testing connection to {config.db_host}:{config.db_port}/{config.db_name}...")

    try:
        db = DatabaseConnection(
            host=config.db_host,
            port=config.db_port,
            database=config.db_name,
            user=config.db_user,
            password=config.db_password,
            sslmode=config.db_sslmode,
        )

        if db.test_connection():
            click.echo("✓ Connection successful!")
        else:
            click.echo("✗ Connection failed", err=True)
            sys.exit(1)

        db.close()

    except Exception as e:
        click.echo(f"✗ Connection failed: {e}", err=True)
        sys.exit(1)


def main():
    """Entry point for CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
