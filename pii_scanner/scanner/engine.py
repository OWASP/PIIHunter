"""
Scanning orchestration engine.

Coordinates column discovery, sampling, PII detection, and results storage.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import structlog

from ..database.discovery import ColumnDiscovery, ColumnCandidate
from ..database.connection import DatabaseConnection
from ..detectors.base import CompositeDetector, DetectedEntity, PIIType
from ..detectors.regex import RegexDetector
from ..detectors.ner import PresidioDetector, SpacyNERDetector
from ..detectors.llm import LLMClassifier
from .sampler import RandomSampler, SampleResult

logger = structlog.get_logger(__name__)


class ScanEngine:
    """
    Main scanning engine that orchestrates the PII discovery process.
    """

    def __init__(
        self,
        db_connection: DatabaseConnection,
        config: Dict[str, Any],
    ):
        """
        Initialize scan engine.

        Args:
            db_connection: DatabaseConnection instance
            config: Configuration dictionary
        """
        self.db = db_connection
        self.config = config
        self.run_id = None

        # Initialize detectors based on config
        self.detector = self._init_detectors()

        # Initialize discovery and sampling
        self.discovery = ColumnDiscovery(db_connection)
        self.sampler = RandomSampler(db_connection)

        logger.info("scan_engine_initialized", config=config)

    def _init_detectors(self) -> CompositeDetector:
        """Initialize the composite detector with enabled detectors."""
        detectors = []

        # Regex detector (always enabled unless explicitly disabled)
        if self.config.get("enable_regex_detection", True):
            regex_detector = RegexDetector(
                confidence=self.config.get("regex_confidence", 0.95)
            )
            detectors.append(regex_detector)
            logger.info("regex_detector_enabled")

        # NER detector (Presidio or spaCy)
        if self.config.get("enable_ner_detection", True):
            try:
                presidio_detector = PresidioDetector(
                    min_confidence=self.config.get("confidence_threshold", 0.5)
                )
                detectors.append(presidio_detector)
                logger.info("presidio_detector_enabled")
            except Exception as e:
                logger.warning(
                    "presidio_detector_failed",
                    error=str(e),
                    message="Falling back to spaCy NER",
                )
                try:
                    spacy_detector = SpacyNERDetector(
                        min_confidence=self.config.get("confidence_threshold", 0.7)
                    )
                    detectors.append(spacy_detector)
                    logger.info("spacy_detector_enabled")
                except Exception as e2:
                    logger.error("ner_detector_unavailable", error=str(e2))

        # LLM detector (optional, disabled by default)
        if self.config.get("enable_llm_detection", False):
            llm_endpoint = self.config.get("llm_endpoint")
            if llm_endpoint:
                try:
                    llm_detector = LLMClassifier(
                        endpoint_url=llm_endpoint,
                        api_key=self.config.get("llm_api_key"),
                        model=self.config.get("llm_model", "llama-2-7b"),
                        min_confidence=self.config.get("confidence_threshold", 0.6),
                    )
                    detectors.append(llm_detector)
                    logger.info("llm_detector_enabled", endpoint=llm_endpoint)
                except Exception as e:
                    logger.error("llm_detector_failed", error=str(e))

        if not detectors:
            logger.warning("no_detectors_enabled")

        return CompositeDetector(detectors)

    def run_scan(
        self,
        schemas: Optional[List[str]] = None,
        exclude_schemas: Optional[List[str]] = None,
        sample_size: Optional[int] = None,
        high_confidence_only: bool = False,
    ) -> int:
        """
        Run a complete PII scan.

        Args:
            schemas: List of schemas to scan (None = all)
            exclude_schemas: Schemas to exclude
            sample_size: Number of rows to sample per column
            high_confidence_only: Only scan columns with high PII likelihood

        Returns:
            Scan run ID
        """
        # Create scan run record
        self.run_id = self._create_scan_run(schemas or [])

        try:
            logger.info(
                "scan_started",
                run_id=self.run_id,
                schemas=schemas,
                exclude_schemas=exclude_schemas,
            )

            # Discover candidate columns
            candidates = self.discovery.discover_columns(
                schemas=schemas,
                exclude_schemas=exclude_schemas,
                include_json=True,
            )

            logger.info(
                "columns_discovered",
                run_id=self.run_id,
                total_candidates=len(candidates),
            )

            # Filter candidates if needed
            if high_confidence_only:
                candidates = [c for c in candidates if c.pii_likelihood_score >= 7.0]
                logger.info(
                    "high_confidence_filter_applied",
                    remaining_candidates=len(candidates),
                )

            # Scan each column
            total_findings = 0
            sample_size = sample_size or self.config.get("sample_size", 1000)

            for idx, candidate in enumerate(candidates):
                logger.info(
                    "scanning_column",
                    progress=f"{idx + 1}/{len(candidates)}",
                    column=candidate.full_column_name,
                    likelihood_score=candidate.pii_likelihood_score,
                )

                findings = self._scan_column(candidate, sample_size)
                total_findings += len(findings)

                # Update column summary
                self._update_column_summary(candidate, findings, sample_size)

            # Mark scan as completed
            self._complete_scan_run(
                status="completed",
                findings_count=total_findings,
                tables_scanned=len(set((c.schema_name, c.table_name) for c in candidates)),
                columns_scanned=len(candidates),
            )

            logger.info(
                "scan_completed",
                run_id=self.run_id,
                total_findings=total_findings,
                columns_scanned=len(candidates),
            )

            return self.run_id

        except Exception as e:
            logger.error(
                "scan_failed",
                run_id=self.run_id,
                error=str(e),
            )
            self._complete_scan_run(
                status="failed",
                error_message=str(e),
            )
            raise

    def _scan_column(
        self,
        candidate: ColumnCandidate,
        sample_size: int,
    ) -> List[Dict[str, Any]]:
        """
        Scan a single column for PII.

        Args:
            candidate: ColumnCandidate to scan
            sample_size: Number of rows to sample

        Returns:
            List of finding dictionaries
        """
        findings = []

        try:
            # Sample column data
            sample_result = self.sampler.sample_column(
                schema_name=candidate.schema_name,
                table_name=candidate.table_name,
                column_name=candidate.column_name,
                sample_size=sample_size,
            )

            # Detect PII in each sampled value
            for sample in sample_result.sample_data:
                value = sample["value"]
                pk = sample["pk"]

                # Skip null or empty values
                if not value or (isinstance(value, str) and not value.strip()):
                    continue

                # Convert to string for text-based detection
                text = str(value)

                # Detect entities
                entities = self.detector.detect(text)

                # Store findings
                for entity in entities:
                    finding = {
                        "run_id": self.run_id,
                        "table_schema": candidate.schema_name,
                        "table_name": candidate.table_name,
                        "column_name": candidate.column_name,
                        "row_pk": json.dumps(pk),
                        "pii_type": entity.entity_type.value,
                        "confidence": entity.confidence,
                        "detector_name": entity.detector_name,
                        "sample_redacted": entity.redacted_text(),
                        "span_start": entity.start,
                        "span_end": entity.end,
                    }

                    findings.append(finding)
                    self._store_finding(finding)

            logger.debug(
                "column_scan_complete",
                column=candidate.full_column_name,
                findings=len(findings),
                sampled_rows=sample_result.sampled_rows,
            )

        except Exception as e:
            logger.error(
                "column_scan_failed",
                column=candidate.full_column_name,
                error=str(e),
            )

        return findings

    def _create_scan_run(self, schemas: List[str]) -> int:
        """Create a new scan run record."""
        sql = """
            INSERT INTO security_pii.scan_runs (
                status,
                config,
                schemas_scanned,
                presidio_version,
                spacy_model,
                triggered_by
            ) VALUES (
                'running',
                %s,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING id
        """

        config_json = json.dumps(self.config)

        # Try to get package versions
        presidio_version = self._get_package_version("presidio-analyzer")
        spacy_model = self.config.get("spacy_model", "en_core_web_lg")
        triggered_by = self.config.get("triggered_by", "manual")

        with self.db.get_connection() as conn:
            conn.set_session(readonly=False)
            with conn.cursor() as cur:
                cur.execute(
                    sql,
                    (config_json, schemas, presidio_version, spacy_model, triggered_by),
                )
                run_id = cur.fetchone()[0]
                conn.commit()

        logger.info("scan_run_created", run_id=run_id)
        return run_id

    def _store_finding(self, finding: Dict[str, Any]):
        """Store a PII finding."""
        sql = """
            INSERT INTO security_pii.findings (
                run_id,
                table_schema,
                table_name,
                column_name,
                row_pk,
                pii_type,
                confidence,
                detector_name,
                sample_redacted,
                span_start,
                span_end
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        """

        self.db.execute_write(
            sql,
            (
                finding["run_id"],
                finding["table_schema"],
                finding["table_name"],
                finding["column_name"],
                finding["row_pk"],
                finding["pii_type"],
                finding["confidence"],
                finding["detector_name"],
                finding["sample_redacted"],
                finding["span_start"],
                finding["span_end"],
            ),
        )

    def _update_column_summary(
        self,
        candidate: ColumnCandidate,
        findings: List[Dict[str, Any]],
        sample_size: int,
    ):
        """Update or create column summary record."""

        # Calculate stats
        pii_types = list(set(f["pii_type"] for f in findings))
        rows_with_pii = len(set(f["row_pk"] for f in findings))

        # Classify column
        if not findings:
            classification = "non_pii"
            classification_confidence = 0.9
        elif rows_with_pii / max(sample_size, 1) > 0.5:
            classification = "pii"
            classification_confidence = 0.95
        elif rows_with_pii / max(sample_size, 1) > 0.1:
            classification = "likely_pii"
            classification_confidence = 0.7
        else:
            classification = "unknown"
            classification_confidence = 0.5

        pii_percentage = (rows_with_pii / max(sample_size, 1)) * 100

        sql = """
            INSERT INTO security_pii.column_summary (
                table_schema,
                table_name,
                column_name,
                column_type,
                last_scan_run_id,
                last_scan_at,
                total_rows_scanned,
                rows_with_pii,
                pii_percentage,
                pii_types_detected,
                classification,
                classification_confidence,
                is_nullable,
                is_unique,
                is_indexed,
                is_primary_key,
                has_foreign_key,
                name_suggests_pii,
                name_patterns_matched
            ) VALUES (
                %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (table_schema, table_name, column_name)
            DO UPDATE SET
                last_scan_run_id = EXCLUDED.last_scan_run_id,
                last_scan_at = EXCLUDED.last_scan_at,
                total_rows_scanned = EXCLUDED.total_rows_scanned,
                rows_with_pii = EXCLUDED.rows_with_pii,
                pii_percentage = EXCLUDED.pii_percentage,
                pii_types_detected = EXCLUDED.pii_types_detected,
                classification = EXCLUDED.classification,
                classification_confidence = EXCLUDED.classification_confidence,
                updated_at = NOW()
        """

        self.db.execute_write(
            sql,
            (
                candidate.schema_name,
                candidate.table_name,
                candidate.column_name,
                candidate.data_type,
                self.run_id,
                sample_size,
                rows_with_pii,
                pii_percentage,
                pii_types,
                classification,
                classification_confidence,
                candidate.is_nullable,
                candidate.is_unique,
                candidate.is_indexed,
                candidate.is_primary_key,
                candidate.has_foreign_key,
                len(candidate.name_patterns_matched) > 0,
                candidate.name_patterns_matched,
            ),
        )

    def _complete_scan_run(
        self,
        status: str,
        findings_count: int = 0,
        tables_scanned: int = 0,
        columns_scanned: int = 0,
        error_message: Optional[str] = None,
    ):
        """Mark scan run as completed."""
        sql = """
            UPDATE security_pii.scan_runs
            SET
                status = %s,
                completed_at = NOW(),
                total_tables_scanned = %s,
                total_columns_scanned = %s,
                pii_findings_count = %s,
                error_message = %s,
                updated_at = NOW()
            WHERE id = %s
        """

        self.db.execute_write(
            sql,
            (status, tables_scanned, columns_scanned, findings_count, error_message, self.run_id),
        )

    def _get_package_version(self, package_name: str) -> Optional[str]:
        """Get installed package version."""
        try:
            import importlib.metadata
            return importlib.metadata.version(package_name)
        except Exception:
            return None
