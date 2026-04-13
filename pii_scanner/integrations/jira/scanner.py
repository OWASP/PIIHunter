"""
Jira PII scanner orchestrator.

Ties together: fetcher → detector → filter → results.
This is the single entry point for all Jira scanning logic.
"""

from typing import List, Tuple, Optional
import structlog

from ...detectors.base import CompositeDetector, PIIType
from .fetcher import JiraFetcher
from .filters import ExceptionFilter
from .models import JiraIssue, JiraComment, PIIFinding, JiraScanResult

logger = structlog.get_logger(__name__)

# How many characters around a PII hit to include as context snippet
SNIPPET_CONTEXT_CHARS = 40


class JiraScanner:
    """
    Scans Jira issues and comments for PII.

    Usage:
        scanner = JiraScanner(detector, exception_filter, fetcher)
        results = scanner.run_full_scan(hours=24)
    """

    def __init__(
        self,
        detector: CompositeDetector,
        exception_filter: ExceptionFilter,
        fetcher: JiraFetcher,
    ):
        self.detector = detector
        self.filter = exception_filter
        self.fetcher = fetcher

    def run_full_scan(self, hours: int = 24) -> List[JiraScanResult]:
        """
        Fetch last N hours of Jira activity and scan all of it for PII.

        Args:
            hours: Lookback window

        Returns:
            List of JiraScanResult — one per scanned piece of content
        """
        issues, comments = self.fetcher.fetch_all(hours=hours)

        results = []

        # Scan issues
        for issue in issues:
            issue_results = self.scan_issue(issue)
            results.extend(issue_results)

        # Scan comments
        for comment in comments:
            result = self.scan_comment(comment)
            results.append(result)

        pii_count = sum(1 for r in results if r.has_pii)
        total_findings = sum(len(r.findings) for r in results)
        total_filtered = sum(r.filtered_count for r in results)

        logger.info(
            "jira_scan_complete",
            total_scanned=len(results),
            items_with_pii=pii_count,
            total_findings=total_findings,
            total_filtered=total_filtered,
        )

        return results

    def scan_issue(self, issue: JiraIssue) -> List[JiraScanResult]:
        """
        Scan an issue's summary and description separately.

        Returns up to 2 results (summary + description).
        """
        results = []

        # Scan summary (title)
        if issue.summary:
            result = self.scan_text(
                text=issue.summary,
                source_type="issue_summary",
                source_id=issue.key,
                issue_key=issue.key,
            )
            results.append(result)

        # Scan description
        if issue.description:
            result = self.scan_text(
                text=issue.description,
                source_type="issue_description",
                source_id=issue.key,
                issue_key=issue.key,
            )
            results.append(result)

        return results

    def scan_comment(self, comment: JiraComment) -> JiraScanResult:
        """Scan a single comment body."""
        return self.scan_text(
            text=comment.body,
            source_type="comment",
            source_id=comment.id,
            issue_key=comment.issue_key,
        )

    def scan_text(
        self,
        text: str,
        source_type: str,
        source_id: str,
        issue_key: str,
    ) -> JiraScanResult:
        """
        Core scan method — run detection + filtering on a single text.

        Args:
            text: The text to scan
            source_type: "issue_summary", "issue_description", or "comment"
            source_id: issue key or comment id
            issue_key: parent issue key

        Returns:
            JiraScanResult
        """
        result = JiraScanResult(
            source_type=source_type,
            source_id=source_id,
            issue_key=issue_key,
        )

        if not text or not text.strip():
            return result

        # Run detection
        entities = self.detector.detect(text)

        if not entities:
            return result

        # Convert entities to PIIFinding objects
        raw_findings = []
        for entity in entities:
            snippet = self._extract_snippet(text, entity.start, entity.end)
            finding = PIIFinding(
                source_type=source_type,
                source_id=source_id,
                issue_key=issue_key,
                pii_type=entity.entity_type.value,
                confidence=entity.confidence,
                detector_name=entity.detector_name,
                redacted_text=entity.redacted_text(),
                original_text_snippet=snippet,
            )
            raw_findings.append(finding)

        # Apply exception filters
        kept_findings, filtered_count = self.filter.apply(raw_findings, text)

        result.findings = kept_findings
        result.filtered_count = filtered_count

        if kept_findings:
            logger.info(
                "pii_found",
                issue_key=issue_key,
                source_type=source_type,
                findings=len(kept_findings),
                filtered=filtered_count,
                types=list({f.pii_type for f in kept_findings}),
            )

        return result

    def _extract_snippet(self, text: str, start: int, end: int) -> str:
        """
        Extract a context window around a detected entity.

        e.g. for entity at chars 50-65, returns chars 10-105 (±40 chars)
        This snippet is used by the filter to check for @mentions.
        """
        snippet_start = max(0, start - SNIPPET_CONTEXT_CHARS)
        snippet_end = min(len(text), end + SNIPPET_CONTEXT_CHARS)
        return text[snippet_start:snippet_end]
