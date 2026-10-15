"""
Jira REST API client.

Handles authentication, HTTP calls, and pagination.
Nothing else — all business logic lives in fetcher.py.

Auth: Basic Auth with email + API token.
  Authorization: Basic base64(email:api_token)
  (handled automatically by requests.auth.HTTPBasicAuth)
"""

from typing import List, Dict, Any, Optional
import requests
from requests.auth import HTTPBasicAuth
import structlog

logger = structlog.get_logger(__name__)


class JiraClient:
    """
    Low-level Jira REST API client.

    Auth: Basic Auth with email + API token.
    """

    def __init__(
        self,
        jira_url: str,
        email: str,
        api_token: str,
        max_results: int = 100,
    ):
        """
        Args:
            jira_url: Base Jira URL e.g. https://yourcompany.atlassian.net
            email: Jira account email
            api_token: Jira API token (generate at id.atlassian.com → Security → API tokens)
            max_results: Max results per paginated request
        """
        self.base_url = jira_url.rstrip("/")
        self.max_results = max_results

        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self.session.auth = HTTPBasicAuth(email, api_token)

        logger.info("jira_client_init", url=self.base_url)

    def search_issues(self, jql: str, fields: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Search issues using JQL. Handles pagination automatically.

        Uses POST /rest/api/3/search/jql with cursor-based pagination
        (nextPageToken) as required by the current Jira Cloud API.

        Args:
            jql: JQL query string
            fields: List of fields to return (None = default fields)

        Returns:
            List of raw issue dicts from Jira API
        """
        fields = fields or ["summary", "description", "reporter", "project", "created", "updated"]

        url = f"{self.base_url}/rest/api/3/search/jql"
        all_issues = []
        next_page_token = None

        logger.info("jira_search_started", jql=jql)

        while True:
            body = {
                "jql": jql,
                "maxResults": self.max_results,
                "fields": fields,
            }

            if next_page_token:
                body["nextPageToken"] = next_page_token

            response = self._post(url, body=body)
            issues = response.get("issues", [])
            all_issues.extend(issues)

            logger.debug("jira_search_page", fetched=len(all_issues))

            next_page_token = response.get("nextPageToken")
            if not next_page_token or not issues:
                break

        logger.info("jira_search_complete", total_issues=len(all_issues))
        return all_issues

    def get_comments(self, issue_key: str) -> List[Dict[str, Any]]:
        """
        Get all comments for an issue.

        Args:
            issue_key: e.g. ENG-123

        Returns:
            List of raw comment dicts
        """
        url = f"{self.base_url}/rest/api/3/issue/{issue_key}/comment"
        all_comments = []
        start_at = 0

        while True:
            params = {
                "startAt": start_at,
                "maxResults": self.max_results,
            }

            response = self._get(url, params=params)
            comments = response.get("comments", [])
            all_comments.extend(comments)

            total = response.get("total", 0)
            start_at += len(comments)

            if start_at >= total or not comments:
                break

        return all_comments

    def test_connection(self) -> bool:
        """Verify credentials and connectivity."""
        try:
            self._get(f"{self.base_url}/rest/api/3/myself")
            logger.info("jira_connection_successful", url=self.base_url)
            return True
        except Exception as e:
            logger.error("jira_connection_failed", error=str(e))
            return False

    def get_myself(self) -> Dict[str, Any]:
        """Return the authenticated user's profile."""
        return self._get(f"{self.base_url}/rest/api/3/myself")

    def get_projects(self) -> List[Dict[str, Any]]:
        """Return all projects accessible to the authenticated user."""
        return self._get(f"{self.base_url}/rest/api/3/project")

    def get_issue(self, issue_key: str) -> Dict[str, Any]:
        """Fetch a single issue by key — used to verify project access."""
        return self._get(f"{self.base_url}/rest/api/3/issue/{issue_key}")

    def _get(self, url: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a GET request, raise on HTTP errors."""
        response = self.session.get(url, params=params, timeout=30)
        self._raise_for_status(response, url)
        return response.json()

    def _post(self, url: str, body: Dict) -> Dict[str, Any]:
        """Make a POST request with a JSON body, raise on HTTP errors."""
        response = self.session.post(url, json=body, timeout=30)
        self._raise_for_status(response, url)
        return response.json()

    def _raise_for_status(self, response, url: str):
        """Raise descriptive errors for common HTTP status codes."""
        if response.status_code == 400:
            try:
                detail = response.json()
            except Exception:
                detail = response.text
            raise ValueError(f"Jira bad request (400): {detail}")
        if response.status_code == 401:
            raise PermissionError("Jira authentication failed. Check email and API token.")
        if response.status_code == 403:
            raise PermissionError("Jira access forbidden. Check project permissions.")
        if response.status_code == 404:
            raise ValueError(f"Jira resource not found: {url}")
        if response.status_code == 410:
            raise ValueError(
                f"Jira endpoint no longer exists (410 Gone): {url}\n"
                "This usually means the API endpoint has been deprecated."
            )
        response.raise_for_status()
