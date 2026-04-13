"""
Report generation for Jira PII scan results.

Saves findings to a JSON or CSV file.
Filename includes date and time by default.
"""

import json
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .models import JiraScanResult
import structlog

logger = structlog.get_logger(__name__)


def generate_filename(fmt: str = "json") -> str:
    """
    Generate a timestamped filename.

    e.g. jira_pii_scan_20260412_143022.json
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"jira_pii_scan_{timestamp}.{fmt}"


def save_report(results: List[JiraScanResult], output_path: str):
    """
    Save scan results to a file.

    Format is determined by the file extension:
      .json  → JSON file
      .csv   → CSV file
      anything else → defaults to JSON

    Args:
        results: List of JiraScanResult from the scanner
        output_path: Full file path to write to
    """
    path = Path(output_path)
    ext = path.suffix.lower()

    # Create parent directories if they don't exist
    path.parent.mkdir(parents=True, exist_ok=True)

    if ext == ".csv":
        _save_csv(results, path)
    else:
        _save_json(results, path)

    logger.info("report_saved", path=str(path))


def _save_json(results: List[JiraScanResult], path: Path):
    """Save results as a structured JSON file."""

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_scanned": len(results),
            "items_with_pii": sum(1 for r in results if r.has_pii),
            "total_findings": sum(len(r.findings) for r in results),
            "total_filtered": sum(r.filtered_count for r in results),
        },
        "findings": [],
    }

    for result in results:
        if not result.has_pii:
            continue

        for finding in result.findings:
            output["findings"].append({
                "issue_key": finding.issue_key,
                "source_type": finding.source_type,
                "source_id": finding.source_id,
                "pii_type": finding.pii_type,
                "confidence": round(finding.confidence, 4),
                "detector": finding.detector_name,
                "redacted_value": finding.redacted_text,
            })

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


def _save_csv(results: List[JiraScanResult], path: Path):
    """Save results as a flat CSV file — one row per finding."""

    fieldnames = [
        "issue_key",
        "source_type",
        "source_id",
        "pii_type",
        "confidence",
        "detector",
        "redacted_value",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for result in results:
            if not result.has_pii:
                continue

            for finding in result.findings:
                writer.writerow({
                    "issue_key": finding.issue_key,
                    "source_type": finding.source_type,
                    "source_id": finding.source_id,
                    "pii_type": finding.pii_type,
                    "confidence": round(finding.confidence, 4),
                    "detector": finding.detector_name,
                    "redacted_value": finding.redacted_text,
                })
