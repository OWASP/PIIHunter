"""
Data models for Jira integration.

Plain dataclasses — no logic, just structure.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class JiraIssue:
    """Represents a Jira issue."""

    key: str                        # e.g. ENG-123
    summary: str                    # issue title
    description: Optional[str]      # issue body (can be None)
    reporter: str                   # display name of reporter
    reporter_email: Optional[str]   # email of reporter
    project_key: str                # e.g. ENG
    created_at: datetime
    updated_at: datetime


@dataclass
class JiraComment:
    """Represents a comment on a Jira issue."""

    id: str
    issue_key: str                  # e.g. ENG-123
    body: str                       # comment text
    author: str                     # display name
    author_email: Optional[str]
    created_at: datetime


@dataclass
class PIIFinding:
    """A single PII hit found in Jira content."""

    source_type: str                # "issue_summary", "issue_description", "comment"
    source_id: str                  # issue key or comment id
    issue_key: str
    pii_type: str                   # EMAIL, PHONE_NUMBER, SSN, etc.
    confidence: float
    detector_name: str
    redacted_text: str              # masked value e.g. j***@***.com
    original_text_snippet: str      # small context window around the hit


@dataclass
class JiraScanResult:
    """Result of scanning a single issue or comment."""

    source_type: str                # "issue" or "comment"
    source_id: str
    issue_key: str
    findings: List[PIIFinding] = field(default_factory=list)
    filtered_count: int = 0         # how many hits were suppressed by filters

    @property
    def has_pii(self) -> bool:
        return len(self.findings) > 0
