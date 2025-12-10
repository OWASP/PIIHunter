"""
Structured logging configuration.

Uses structlog to prevent PII leakage in logs and provide
JSON-formatted output for easy parsing.
"""

import logging
import sys
import structlog
from typing import Any


def configure_logging(log_level: str = "INFO", log_format: str = "json"):
    """
    Configure structured logging.

    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR)
        log_format: Output format ("json" or "console")
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    # Choose processors based on format
    if log_format == "json":
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            _sanitize_processor,  # Remove potential PII
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Console-friendly format with colors
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            _sanitize_processor,  # Remove potential PII
            structlog.dev.ConsoleRenderer(),
        ]

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def _sanitize_processor(logger: Any, method_name: str, event_dict: dict) -> dict:
    """
    Processor to sanitize log entries and prevent PII leakage.

    Redacts fields that might contain sensitive data.
    """
    # Fields that should never be logged in full
    sensitive_fields = {
        "password",
        "api_key",
        "secret",
        "token",
        "auth",
        "credit_card",
        "ssn",
        "email",
        "phone",
    }

    for key in list(event_dict.keys()):
        key_lower = key.lower()

        # Check if key contains sensitive terms
        if any(term in key_lower for term in sensitive_fields):
            event_dict[key] = "[REDACTED]"

        # Truncate very long strings (potential data leakage)
        if isinstance(event_dict[key], str) and len(event_dict[key]) > 200:
            event_dict[key] = event_dict[key][:200] + "... [TRUNCATED]"

    return event_dict


def get_logger(name: str):
    """
    Get a structured logger instance.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Structured logger instance
    """
    return structlog.get_logger(name)
