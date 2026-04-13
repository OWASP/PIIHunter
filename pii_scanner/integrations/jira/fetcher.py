"""
Fetches Jira issues and comments from the last N hours.

Owns the JQL query building and raw API response parsing.
Returns clean model objects — no raw dicts leave this file.
"""

from typing import List, Optional, Tuple
from datetime import datetime, timezone
import structlog

from .client import JiraClient
from .models import JiraIssue, JiraComment

logger = structlog.get_logger(__name__)


class JiraFetcher:
    """
    Fetches recent Jira activity using JQL.

    Handles:
    - New issues created in last N hours
    - Issues with new comments in last N hours
    - Parses raw API responses into clean model objects
    """

    def __init__(self, client: JiraClient, project_keys: Optional[List[str]] = None):
        """
        Args:
            client: JiraClient instance
            project_keys: Optional list of project keys to filter by.
                          If None or empty, fetches from all accessible projects.
        """
        self.client = client
        self.project_keys = [k.strip().upper() for k in project_keys] if project_keys else []

    def fetch_all(self, hours: int = 24) -> Tuple[List[JiraIssue], List[JiraComment]]:
        """
        Fetch all new issues and comments from the last N hours.

        Args:
            hours: Lookback window in hours (default 24)

        Returns:
            Tuple of (issues, comments)
        """
        logger.info("jira_fetch_started", hours=hours, projects=self.project_keys or "all")

        issues = self.fetch_new_issues(hours)
        comments = self.fetch_new_comments(hours)

        logger.info(
            "jira_fetch_complete",
            new_issues=len(issues),
            new_comments=len(comments),
        )

        return issues, comments

    def fetch_new_issues(self, hours: int = 24) -> List[JiraIssue]:
        """
        Fetch issues created in the last N hours.

        Args:
            hours: Lookback window in hours

        Returns:
            List of JiraIssue objects
        """
        since_str = self._jql_datetime(hours)
        jql = self._build_jql(f'created >= "{since_str}" ORDER BY created DESC')
        raw_issues = self.client.search_issues(jql)

        issues = [self._parse_issue(raw) for raw in raw_issues]
        logger.info("new_issues_fetched", count=len(issues), since=since_str)
        return issues

    def fetch_new_comments(self, hours: int = 24) -> List[JiraComment]:
        """
        Fetch comments added in the last N hours.

        Jira doesn't support direct comment JQL, so we:
        1. Find issues updated in last N hours
        2. Fetch their comments and filter to only recent ones

        Args:
            hours: Lookback window in hours

        Returns:
            List of JiraComment objects
        """
        since_str = self._jql_datetime(hours)
        # Find issues that were updated (could be new comment, status change, etc.)
        jql = self._build_jql(f'updated >= "{since_str}" ORDER BY updated DESC')
        raw_issues = self.client.search_issues(jql)

        cutoff = self._hours_ago_timestamp(hours)
        all_comments = []

        for raw_issue in raw_issues:
            issue_key = raw_issue["key"]
            raw_comments = self.client.get_comments(issue_key)

            for raw_comment in raw_comments:
                comment = self._parse_comment(raw_comment, issue_key)

                # Only keep comments created within our window
                if comment.created_at >= cutoff:
                    all_comments.append(comment)

        logger.info("new_comments_fetched", count=len(all_comments))
        return all_comments

    def _build_jql(self, time_filter: str) -> str:
        """Build JQL with optional project filter."""
        if self.project_keys:
            project_clause = f"project IN ({', '.join(self.project_keys)}) AND "
        else:
            project_clause = ""

        return f"{project_clause}{time_filter}"

    def _parse_issue(self, raw: dict) -> JiraIssue:
        """Parse raw Jira API issue dict into JiraIssue."""
        fields = raw.get("fields", {})
        reporter = fields.get("reporter") or {}

        return JiraIssue(
            key=raw["key"],
            summary=fields.get("summary", ""),
            description=self._extract_text(fields.get("description")),
            reporter=reporter.get("displayName", "Unknown"),
            reporter_email=reporter.get("emailAddress"),
            project_key=fields.get("project", {}).get("key", ""),
            created_at=self._parse_datetime(fields.get("created", "")),
            updated_at=self._parse_datetime(fields.get("updated", "")),
        )

    def _parse_comment(self, raw: dict, issue_key: str) -> JiraComment:
        """Parse raw Jira API comment dict into JiraComment."""
        author = raw.get("author") or {}

        return JiraComment(
            id=raw["id"],
            issue_key=issue_key,
            body=self._extract_text(raw.get("body")),
            author=author.get("displayName", "Unknown"),
            author_email=author.get("emailAddress"),
            created_at=self._parse_datetime(raw.get("created", "")),
        )

    def _extract_text(self, content) -> Optional[str]:
        """
        Extract plain text from Jira's Atlassian Document Format (ADF) or plain string.

        Jira Cloud returns description/body as ADF (nested JSON).
        Jira Server returns plain text strings.
        """
        if content is None:
            return None

        # Plain string (Jira Server)
        if isinstance(content, str):
            return content

        # ADF format (Jira Cloud) — recursively extract text nodes
        if isinstance(content, dict):
            return self._extract_adf_text(content)

        return None

    def _extract_adf_text(self, node: dict) -> str:
        """Recursively extract plain text from ADF document node."""
        text_parts = []

        if node.get("type") == "text":
            text_parts.append(node.get("text", ""))

        for child in node.get("content", []):
            text_parts.append(self._extract_adf_text(child))

        return " ".join(part for part in text_parts if part).strip()

    def _parse_datetime(self, dt_str: str) -> datetime:
        """Parse Jira's ISO datetime string to timezone-aware datetime."""
        if not dt_str:
            return datetime.now(timezone.utc)
        try:
            # Jira returns format: 2024-01-15T14:30:00.000+0000
            return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)

    def _hours_ago_timestamp(self, hours: int) -> datetime:
        """Return timezone-aware datetime for N hours ago."""
        from datetime import timedelta
        return datetime.now(timezone.utc) - timedelta(hours=hours)

    def _jql_datetime(self, hours: int) -> str:
        """
        Return an absolute datetime string in Jira JQL format.

        Jira JQL expects: "yyyy/MM/dd HH:mm"
        Using absolute datetime instead of relative (-Nh) avoids
        inconsistencies with the Jira Cloud API.
        """
        from datetime import timedelta
        dt = datetime.now(timezone.utc) - timedelta(hours=hours)
        return dt.strftime("%Y/%m/%d %H:%M")
