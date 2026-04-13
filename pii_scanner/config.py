"""
Configuration management using pydantic-settings.

Loads configuration from environment variables and .env files.
"""

from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    """
    Application configuration.

    All settings can be overridden via environment variables.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database connection
    db_host: str = Field(default="localhost", description="PostgreSQL host")
    db_port: int = Field(default=5432, description="PostgreSQL port")
    db_name: str = Field(..., description="Database name")
    db_user: str = Field(..., description="Database user (read-only role)")
    db_password: str = Field(..., description="Database password")
    db_sslmode: str = Field(default="require", description="SSL mode")

    # Scanning configuration
    schemas_to_scan: str = Field(
        default="public",
        description="Comma-separated list of schemas to scan",
    )
    schemas_to_exclude: str = Field(
        default="pg_catalog,information_schema,pg_toast",
        description="Comma-separated list of schemas to exclude",
    )
    sample_size: int = Field(
        default=1000,
        description="Number of rows to sample per column",
    )
    batch_size: int = Field(
        default=500,
        description="Batch size for streaming operations",
    )
    max_workers: int = Field(
        default=4,
        description="Maximum number of parallel workers",
    )

    # PII detection settings
    confidence_threshold: float = Field(
        default=0.5,
        description="Minimum confidence threshold (0.0-1.0)",
    )
    enable_regex_detection: bool = Field(
        default=True,
        description="Enable regex-based detection",
    )
    enable_ner_detection: bool = Field(
        default=True,
        description="Enable NER-based detection (Presidio/spaCy)",
    )
    enable_llm_detection: bool = Field(
        default=False,
        description="Enable LLM-based detection (self-hosted only)",
    )

    # LLM configuration (optional, for self-hosted endpoints only)
    llm_endpoint: Optional[str] = Field(
        default=None,
        description="LLM endpoint URL (must be self-hosted)",
    )
    llm_api_key: Optional[str] = Field(
        default=None,
        description="LLM API key",
    )
    llm_model: str = Field(
        default="llama-2-7b",
        description="LLM model name",
    )

    # Logging
    log_level: str = Field(
        default="INFO",
        description="Log level (DEBUG, INFO, WARNING, ERROR)",
    )
    log_format: str = Field(
        default="json",
        description="Log format (json or console)",
    )

    # Jira integration
    jira_url: Optional[str] = Field(
        default=None,
        description="Jira base URL e.g. https://yourcompany.atlassian.net",
    )
    jira_email: Optional[str] = Field(
        default=None,
        description="Jira account email — only needed for classic (non-scoped) tokens",
    )
    jira_api_token: Optional[str] = Field(
        default=None,
        description="Jira API token (generate at id.atlassian.com)",
    )
    jira_project_keys: Optional[str] = Field(
        default=None,
        description="Comma-separated Jira project keys to scan. Leave empty to scan all.",
    )
    jira_webhook_secret: Optional[str] = Field(
        default=None,
        description="Secret for verifying Jira webhook signatures",
    )
    jira_webhook_port: int = Field(
        default=8080,
        description="Port for the Jira webhook server",
    )
    company_email_domains: Optional[str] = Field(
        default=None,
        description="Comma-separated company email domains to exclude from PII findings",
    )

    # Runtime metadata
    triggered_by: str = Field(
        default="manual",
        description="Who/what triggered the scan",
    )

    @field_validator("confidence_threshold")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Validate confidence threshold is in valid range."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence_threshold must be between 0.0 and 1.0")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        return v.upper()

    @field_validator("log_format")
    @classmethod
    def validate_log_format(cls, v: str) -> str:
        """Validate log format."""
        valid_formats = {"json", "console"}
        if v.lower() not in valid_formats:
            raise ValueError(f"log_format must be one of {valid_formats}")
        return v.lower()

    def get_schemas_to_scan(self) -> List[str]:
        """Parse schemas_to_scan into a list."""
        return [s.strip() for s in self.schemas_to_scan.split(",") if s.strip()]

    def get_schemas_to_exclude(self) -> List[str]:
        """Parse schemas_to_exclude into a list."""
        return [s.strip() for s in self.schemas_to_exclude.split(",") if s.strip()]

    def get_jira_project_keys(self) -> List[str]:
        """Parse jira_project_keys into a list. Returns empty list if not set."""
        if not self.jira_project_keys:
            return []
        return [k.strip() for k in self.jira_project_keys.split(",") if k.strip()]

    def get_company_email_domains(self) -> List[str]:
        """Parse company_email_domains into a list. Returns empty list if not set."""
        if not self.company_email_domains:
            return []
        return [d.strip() for d in self.company_email_domains.split(",") if d.strip()]

    def to_dict(self) -> dict:
        """Convert config to dictionary for storage."""
        return {
            "sample_size": self.sample_size,
            "batch_size": self.batch_size,
            "confidence_threshold": self.confidence_threshold,
            "enable_regex": self.enable_regex_detection,
            "enable_ner": self.enable_ner_detection,
            "enable_llm": self.enable_llm_detection,
            "schemas_scanned": self.get_schemas_to_scan(),
            "schemas_excluded": self.get_schemas_to_exclude(),
        }


def load_config() -> Config:
    """
    Load configuration from environment.

    Returns:
        Config instance

    Raises:
        ValidationError: If configuration is invalid
    """
    return Config()
