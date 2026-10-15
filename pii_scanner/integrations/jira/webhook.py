"""
Jira webhook receiver (Option 2).

Starts a FastAPI server that listens for real-time Jira events.
Scans incoming issues/comments for PII immediately as they arrive.

Supported events:
  - jira:issue_created
  - comment_created
"""

import hashlib
import hmac
import json
from typing import Optional
from datetime import datetime, timezone
import structlog

logger = structlog.get_logger(__name__)


def create_webhook_app(scanner, webhook_secret: Optional[str] = None):
    """
    Create and return a FastAPI app for receiving Jira webhooks.

    Args:
        scanner: JiraScanner instance
        webhook_secret: Optional secret for HMAC signature verification.
                        If None, signature verification is skipped (not recommended for prod).

    Returns:
        FastAPI app instance
    """
    try:
        from fastapi import FastAPI, Request, HTTPException
        from fastapi.responses import JSONResponse
    except ImportError:
        raise ImportError(
            "fastapi and uvicorn are required for webhook mode.\n"
            "Install with: pip install fastapi uvicorn"
        )

    if webhook_secret is None:
        raise ValueError(
            "JIRA_WEBHOOK_SECRET must be set before starting the webhook server. "
            "Running without a secret allows any caller to send arbitrary events. "
            "Set JIRA_WEBHOOK_SECRET in your .env file."
        )

    app = FastAPI(title="PIIHunter Jira Webhook", version="1.0.0")

    @app.get("/health")
    async def health():
        """Health check endpoint."""
        return {"status": "ok"}

    @app.post("/webhook")
    async def receive_webhook(request: Request):
        """
        Receive Jira webhook events.

        Jira sends a POST with JSON body for each event.
        We verify the signature (if secret configured), parse the event,
        and run PII detection on the content.
        """
        body = await request.body()

        # Verify HMAC signature if secret is configured
        if webhook_secret:
            if not _verify_signature(body, webhook_secret, request.headers):
                logger.warning("webhook_invalid_signature")
                raise HTTPException(status_code=401, detail="Invalid signature")

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

        event_type = payload.get("webhookEvent", "")
        logger.info("webhook_received", event=event_type)

        # Route to appropriate handler
        if event_type == "jira:issue_created":
            results = _handle_issue_created(payload, scanner)

        elif event_type == "comment_created":
            results = _handle_comment_created(payload, scanner)

        else:
            # Unhandled event type — acknowledge and ignore
            logger.debug("webhook_event_ignored", event=event_type)
            return JSONResponse({"status": "ignored", "event": event_type})

        # Build response summary
        findings_count = sum(len(r.findings) for r in results)
        items_with_pii = [r.issue_key for r in results if r.has_pii]

        return JSONResponse({
            "status": "processed",
            "event": event_type,
            "findings": findings_count,
            "pii_detected_in": items_with_pii,
        })

    return app


def _handle_issue_created(payload: dict, scanner) -> list:
    """Handle jira:issue_created event."""
    from .models import JiraIssue

    issue_data = payload.get("issue", {})
    fields = issue_data.get("fields", {})
    reporter = fields.get("reporter") or {}

    issue = JiraIssue(
        key=issue_data.get("key", "UNKNOWN"),
        summary=fields.get("summary", ""),
        description=scanner.fetcher._extract_text(fields.get("description")),
        reporter=reporter.get("displayName", "Unknown"),
        reporter_email=reporter.get("emailAddress"),
        project_key=fields.get("project", {}).get("key", ""),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    logger.info("webhook_scanning_issue", key=issue.key)
    return scanner.scan_issue(issue)


def _handle_comment_created(payload: dict, scanner) -> list:
    """Handle comment_created event."""
    from .models import JiraComment

    comment_data = payload.get("comment", {})
    issue_data = payload.get("issue", {})
    author = comment_data.get("author") or {}

    comment = JiraComment(
        id=comment_data.get("id", "unknown"),
        issue_key=issue_data.get("key", "UNKNOWN"),
        body=scanner.fetcher._extract_text(comment_data.get("body", "")),
        author=author.get("displayName", "Unknown"),
        author_email=author.get("emailAddress"),
        created_at=datetime.now(timezone.utc),
    )

    logger.info("webhook_scanning_comment", issue=comment.issue_key, comment_id=comment.id)
    return [scanner.scan_comment(comment)]


def _verify_signature(body: bytes, secret: str, headers) -> bool:
    """
    Verify Jira webhook HMAC-SHA256 signature.

    Jira sends the signature in the X-Hub-Signature header as:
    sha256=<hex_digest>
    """
    signature_header = headers.get("X-Hub-Signature", "")

    if not signature_header.startswith("sha256="):
        return False

    expected_sig = signature_header[len("sha256="):]
    computed_sig = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected_sig, computed_sig)


def run_webhook_server(scanner, host: str = "0.0.0.0", port: int = 8080, secret: Optional[str] = None):
    """
    Start the webhook server.

    Args:
        scanner: JiraScanner instance
        host: Host to bind to
        port: Port to listen on
        secret: Webhook secret for signature verification
    """
    try:
        import uvicorn
    except ImportError:
        raise ImportError(
            "uvicorn is required to run the webhook server.\n"
            "Install with: pip install uvicorn"
        )

    app = create_webhook_app(scanner, webhook_secret=secret)

    if host == "0.0.0.0":
        logger.warning(
            "webhook_binding_all_interfaces",
            message=(
                "Server is binding to 0.0.0.0 (all interfaces). "
                "Restrict to a specific interface (e.g. 127.0.0.1) behind a reverse proxy in production."
            ),
        )
    logger.info("webhook_server_starting", host=host, port=port)
    uvicorn.run(app, host=host, port=port)
