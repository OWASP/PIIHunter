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
        click.echo("Error loading configuration. Check logs for details.", err=True)
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
        click.echo("✗ Schema initialization failed. Check logs for details.", err=True)
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
        click.echo("✗ Schema drop failed. Check logs for details.", err=True)
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
        click.echo("✗ Discovery failed. Check logs for details.", err=True)
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
        click.echo("\n✗ Scan failed. Check logs for details.", err=True)
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
        click.echo("✗ Report generation failed. Check logs for details.", err=True)
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
        click.echo("✗ Connection failed. Check logs for details.", err=True)
        sys.exit(1)


@cli.group()
@click.pass_context
def jira(ctx):
    """Jira integration — scan issues and comments for PII."""
    config: Config = ctx.obj["config"]

    # Validate Jira config is present
    if not config.jira_api_token:
        click.echo("✗ JIRA_API_TOKEN not set in .env", err=True)
        sys.exit(1)

    if not config.jira_url or not config.jira_email:
        click.echo(
            "✗ Jira configuration missing. Set JIRA_URL, JIRA_EMAIL, and JIRA_API_TOKEN in .env",
            err=True,
        )
        sys.exit(1)


@jira.command("test")
@click.pass_context
def jira_test(ctx):
    """Test Jira connectivity, permissions, and issue access."""
    config: Config = ctx.obj["config"]

    from .integrations.jira.client import JiraClient

    client = JiraClient(
        jira_url=config.jira_url,
        email=config.jira_email,
        api_token=config.jira_api_token,
    )

    click.echo(f"\nTesting connection to {config.jira_url}...\n")

    # Step 1 — Auth check
    try:
        me = client.get_myself()
        click.echo(f"  Auth          ✓  logged in as {me.get('displayName')} ({me.get('emailAddress')})")
    except Exception as e:
        click.echo(f"  Auth          ✗  {e}", err=True)
        sys.exit(1)

    # Step 2 — List accessible projects
    try:
        projects = client.get_projects()
        keys = [p["key"] for p in projects]
        click.echo(f"  Projects      ✓  {len(keys)} accessible: {', '.join(keys) if keys else 'none'}")
    except Exception as e:
        click.echo(f"  Projects      ✗  {e}", err=True)

    # Step 3 — Check configured project keys exist
    configured_keys = config.get_jira_project_keys()
    if configured_keys:
        accessible_keys = {p["key"] for p in projects}
        for key in configured_keys:
            if key in accessible_keys:
                click.echo(f"  Project {key:<8} ✓  accessible")
            else:
                click.echo(f"  Project {key:<8} ✗  not found or no access")

    # Step 4 — Try fetching issues without any time filter
    try:
        jql = f"project IN ({', '.join(configured_keys)}) ORDER BY created DESC" \
            if configured_keys else "ORDER BY created DESC"
        issues = client.search_issues(jql)
        if issues:
            click.echo(f"\n  Recent issues (no time filter):")
            for issue in issues[:5]:
                fields = issue.get("fields", {})
                click.echo(f"    {issue['key']}  {fields.get('summary', '')[:60]}")
        else:
            click.echo(f"\n  No issues found even without a time filter.")
            click.echo(f"  → The project may be empty or the API token lacks Browse permissions.")
    except Exception as e:
        click.echo(f"  Issue search  ✗  {e}", err=True)

    click.echo()


@jira.command("scan")
@click.option("--hours", type=int, default=24, help="Lookback window in hours (default 24)")
@click.option("--output", default=None, help="Output file path. Supports .json and .csv extensions. Auto-generated if not specified.")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "csv"]), help="Output format when auto-generating filename (default: json)")
@click.pass_context
def jira_scan(ctx, hours: int, output: Optional[str], fmt: str):
    """Fetch Jira activity from the last N hours and scan for PII."""
    config: Config = ctx.obj["config"]

    from .integrations.jira.reporter import generate_filename
    from datetime import datetime, timezone, timedelta

    # Auto-generate output filename if not provided
    output_path = output or generate_filename(fmt)

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    since_str = since.strftime("%Y-%m-%d %H:%M UTC")

    click.echo("=" * 60)
    click.echo("JIRA PII SCAN")
    click.echo("=" * 60)
    click.echo(f"Jira URL:         {config.jira_url}")
    click.echo(f"Projects:         {', '.join(config.get_jira_project_keys()) or 'ALL'}")
    click.echo(f"Lookback:         last {hours} hours (since {since_str})")
    click.echo(f"Detectors:        regex={config.enable_regex_detection}, "
               f"ner={config.enable_ner_detection}, llm={config.enable_llm_detection}")
    click.echo(f"Ignoring domains: {', '.join(config.get_company_email_domains()) or 'none configured'}")
    click.echo(f"Output file:      {output_path}")
    click.echo("=" * 60)
    click.echo()

    try:
        from .integrations.jira.client import JiraClient
        from .integrations.jira.fetcher import JiraFetcher
        from .integrations.jira.filters import ExceptionFilter
        from .integrations.jira.scanner import JiraScanner
        from .integrations.jira.reporter import save_report

        detector = _build_detector(config)

        client = JiraClient(
            jira_url=config.jira_url,
            email=config.jira_email,
            api_token=config.jira_api_token,
        )
        fetcher = JiraFetcher(client, project_keys=config.get_jira_project_keys())
        exception_filter = ExceptionFilter(company_domains=config.get_company_email_domains())
        scanner = JiraScanner(detector, exception_filter, fetcher)

        click.echo("Scanning...")
        results = scanner.run_full_scan(hours=hours)

        # Print to terminal
        _print_jira_report(results)

        # Save to file
        save_report(results, output_path)
        click.echo(f"\n✓ Report saved to: {output_path}")

    except Exception as e:
        logger.error("jira_scan_failed", error=str(e))
        click.echo("\n✗ Jira scan failed. Check logs for details.", err=True)
        sys.exit(1)


@jira.command("webhook")
@click.option("--port", type=int, default=None, help="Port to listen on (default from .env or 8080)")
@click.pass_context
def jira_webhook(ctx, port: Optional[int]):
    """Start a webhook server to scan Jira events in real time."""
    config: Config = ctx.obj["config"]
    port = port or config.jira_webhook_port

    click.echo("=" * 60)
    click.echo("JIRA WEBHOOK SERVER")
    click.echo("=" * 60)
    click.echo(f"Listening on:  http://0.0.0.0:{port}/webhook")
    click.echo(f"Health check:  http://0.0.0.0:{port}/health")
    click.echo(f"Signature:     {'enabled' if config.jira_webhook_secret else 'disabled (no secret set)'}")
    click.echo("=" * 60)
    click.echo()

    try:
        from .integrations.jira.client import JiraClient
        from .integrations.jira.fetcher import JiraFetcher
        from .integrations.jira.filters import ExceptionFilter
        from .integrations.jira.scanner import JiraScanner
        from .integrations.jira.webhook import run_webhook_server

        detector = _build_detector(config)
        client = JiraClient(
            jira_url=config.jira_url,
            email=config.jira_email,
            api_token=config.jira_api_token,
        )
        fetcher = JiraFetcher(client, project_keys=config.get_jira_project_keys())
        exception_filter = ExceptionFilter(company_domains=config.get_company_email_domains())
        scanner = JiraScanner(detector, exception_filter, fetcher)

        run_webhook_server(
            scanner=scanner,
            port=port,
            secret=config.jira_webhook_secret,
        )

    except Exception as e:
        logger.error("jira_webhook_failed", error=str(e))
        click.echo("\n✗ Webhook server failed. Check logs for details.", err=True)
        sys.exit(1)


def _build_detector(config: Config):
    """Build the CompositeDetector from config. Shared by DB and Jira scanners."""
    from .detectors.base import CompositeDetector
    from .detectors.regex import RegexDetector
    from .detectors.ner import PresidioDetector, SpacyNERDetector

    detectors = []

    if config.enable_regex_detection:
        detectors.append(RegexDetector())

    if config.enable_ner_detection:
        try:
            detectors.append(PresidioDetector(min_confidence=config.confidence_threshold))
        except Exception:
            try:
                detectors.append(SpacyNERDetector(min_confidence=config.confidence_threshold))
            except Exception:
                pass

    return CompositeDetector(detectors)


def _print_jira_report(results):
    """Print a formatted Jira scan report to the terminal."""
    total_findings = sum(len(r.findings) for r in results)
    total_filtered = sum(r.filtered_count for r in results)
    items_with_pii = [r for r in results if r.has_pii]

    click.echo(f"\n{'=' * 60}")
    click.echo("RESULTS")
    click.echo(f"{'=' * 60}")
    click.echo(f"Items scanned:  {len(results)}")
    click.echo(f"Items with PII: {len(items_with_pii)}")
    click.echo(f"Total findings: {total_findings}")
    click.echo(f"Filtered out:   {total_filtered} (@mentions / company emails)")

    if not items_with_pii:
        click.echo("\n✓ No PII found.")
        return

    click.echo(f"\n{'─' * 60}")

    for result in items_with_pii:
        click.echo(f"\n[{result.issue_key}] {result.source_type}")
        click.echo(f"  {'PII Type':<20} {'Confidence':<12} {'Detector':<12} {'Redacted'}")
        click.echo(f"  {'─' * 70}")
        for finding in result.findings:
            click.echo(
                f"  {finding.pii_type:<20} "
                f"{finding.confidence:<12.2f} "
                f"{finding.detector_name:<12} "
                f"{finding.redacted_text}"
            )


def main():
    """Entry point for CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
