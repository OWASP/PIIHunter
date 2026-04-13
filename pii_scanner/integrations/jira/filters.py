"""
Exception filters for Jira PII detection.

Suppresses false positives that are expected/legitimate:
  1. @mention names  — @john in a comment is intentional, not accidental PII
  2. Company emails  — internal email addresses should not be flagged
"""

import re
from typing import List, Set
from ..jira.models import PIIFinding
import structlog

logger = structlog.get_logger(__name__)

# Matches @username mentions (letters, digits, dots, hyphens, underscores)
MENTION_PATTERN = re.compile(r"@([\w.\-]+)")


class ExceptionFilter:
    """
    Filters out PII findings that are known/expected in a Jira context.

    Rules:
    - PERSON entities whose text matches a @mention in the same text are dropped
    - EMAIL entities whose domain matches a company domain are dropped
    """

    def __init__(self, company_domains: List[str]):
        """
        Args:
            company_domains: List of internal email domains to ignore.
                             e.g. ["company.com", "internal.company.com"]
        """
        self.company_domains = {d.lower().strip() for d in company_domains if d.strip()}

    def apply(self, findings: List[PIIFinding], original_text: str) -> tuple:
        """
        Apply all exception rules to a list of findings.

        Args:
            findings: Raw findings from the detector
            original_text: The original text that was scanned (needed for @mention extraction)

        Returns:
            Tuple of (kept_findings, filtered_count)
        """
        mentions = self._extract_mentions(original_text)

        kept = []
        filtered_count = 0

        for finding in findings:
            if self._is_mention_name(finding, mentions):
                logger.debug(
                    "finding_filtered_mention",
                    pii_type=finding.pii_type,
                    redacted=finding.redacted_text,
                )
                filtered_count += 1
                continue

            if self._is_company_email(finding):
                logger.debug(
                    "finding_filtered_company_email",
                    redacted=finding.redacted_text,
                )
                filtered_count += 1
                continue

            kept.append(finding)

        return kept, filtered_count

    def _extract_mentions(self, text: str) -> Set[str]:
        """
        Extract all @mention usernames from text.

        e.g. "hey @john.doe can you check this" → {"john.doe", "john"}
        We store both the full mention and the first part before any dot/underscore
        to catch cases where the name is "John Doe" but mention is "@john.doe".
        """
        mentions = set()
        for match in MENTION_PATTERN.finditer(text):
            username = match.group(1).lower()
            mentions.add(username)

            # Also add first segment — @john.doe → "john"
            first_part = re.split(r"[._\-]", username)[0]
            if first_part:
                mentions.add(first_part)

        return mentions

    def _is_mention_name(self, finding: PIIFinding, mentions: Set[str]) -> bool:
        """
        Check if a PERSON finding matches a @mention in the text.

        Comparison is case-insensitive and checks if any mention token
        appears in the detected name.
        """
        if finding.pii_type != "PERSON":
            return False

        if not mentions:
            return False

        # Extract raw name from redacted text context
        # Use original_text_snippet for comparison
        snippet_lower = finding.original_text_snippet.lower()

        for mention in mentions:
            if mention in snippet_lower:
                return True

        return False

    def _is_company_email(self, finding: PIIFinding) -> bool:
        """
        Check if an EMAIL finding belongs to a company domain.
        """
        if finding.pii_type != "EMAIL":
            return False

        if not self.company_domains:
            return False

        # Extract domain from redacted text — we stored "j***@***.com"
        # so we need the original snippet to get the real domain
        snippet = finding.original_text_snippet

        # Find email-like pattern in snippet
        email_match = re.search(r"[\w._%+-]+@([\w.-]+\.[a-zA-Z]{2,})", snippet)
        if not email_match:
            return False

        domain = email_match.group(1).lower()
        return domain in self.company_domains
