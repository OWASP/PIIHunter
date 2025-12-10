"""
Base interfaces for PII detection.

Defines the common interface that all detectors must implement.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum


class PIIType(str, Enum):
    """Standard PII types detected by the system."""

    # Contact information
    EMAIL = "EMAIL"
    PHONE_NUMBER = "PHONE_NUMBER"
    URL = "URL"
    IP_ADDRESS = "IP_ADDRESS"

    # Government identifiers
    SSN = "SSN"
    US_PASSPORT = "US_PASSPORT"
    US_DRIVER_LICENSE = "US_DRIVER_LICENSE"

    # Financial
    CREDIT_CARD = "CREDIT_CARD"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    IBAN = "IBAN"
    ROUTING_NUMBER = "ROUTING_NUMBER"

    # Personal identifiers
    PERSON_NAME = "PERSON"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    AGE = "AGE"

    # Location
    ADDRESS = "ADDRESS"
    LOCATION = "LOCATION"
    ZIP_CODE = "ZIP_CODE"

    # Medical
    MEDICAL_LICENSE = "MEDICAL_LICENSE"

    # Crypto
    CRYPTO_WALLET = "CRYPTO_WALLET"

    # Authentication
    PASSWORD = "PASSWORD"
    API_KEY = "API_KEY"
    AUTH_TOKEN = "AUTH_TOKEN"

    # Generic
    DATE_TIME = "DATE_TIME"
    UNKNOWN = "UNKNOWN"


@dataclass
class DetectedEntity:
    """Represents a detected PII entity."""

    entity_type: PIIType
    confidence: float  # 0.0 to 1.0
    start: int  # Character position in text
    end: int  # Character position in text
    detector_name: str  # Which detector found this
    text: Optional[str] = None  # The actual matched text (optional, for debugging)

    def __post_init__(self):
        """Validate fields."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0 and 1, got {self.confidence}")
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"Invalid span: start={self.start}, end={self.end}")

    def redacted_text(self, max_length: int = 50) -> str:
        """
        Return a redacted version of the matched text for safe storage.

        Args:
            max_length: Maximum length of redacted text

        Returns:
            Redacted string like "j***@***.com" or "[PERSON]"
        """
        if not self.text:
            return f"[{self.entity_type.value}]"

        text = self.text[:max_length]

        # Simple redaction: show first and last char, mask the middle
        if len(text) <= 3:
            return "*" * len(text)

        if self.entity_type == PIIType.EMAIL:
            # Show first char of local part and domain
            parts = text.split("@")
            if len(parts) == 2:
                return f"{parts[0][0]}***@***.{parts[1].split('.')[-1] if '.' in parts[1] else '***'}"

        if self.entity_type == PIIType.PHONE_NUMBER:
            # Show last 4 digits
            digits = "".join(c for c in text if c.isdigit())
            if len(digits) >= 4:
                return f"***-***-{digits[-4:]}"

        if self.entity_type in (PIIType.SSN, PIIType.CREDIT_CARD):
            # Show last 4 characters
            return f"***-**-{text[-4:]}" if len(text) >= 4 else "****"

        # Generic redaction
        return f"{text[0]}{'*' * min(len(text) - 2, 10)}{text[-1]}"


class PIIDetector(ABC):
    """
    Abstract base class for PII detectors.

    All detectors (regex, NER, LLM) must implement this interface.
    """

    def __init__(self, name: str):
        """
        Initialize detector.

        Args:
            name: Unique name for this detector
        """
        self.name = name

    @abstractmethod
    def detect(self, text: str) -> List[DetectedEntity]:
        """
        Detect PII entities in the given text.

        Args:
            text: Input text to analyze

        Returns:
            List of DetectedEntity objects found in the text
        """
        pass

    @abstractmethod
    def supports_entity_type(self, entity_type: PIIType) -> bool:
        """
        Check if this detector can detect the given entity type.

        Args:
            entity_type: PIIType to check

        Returns:
            True if this detector supports the entity type
        """
        pass

    def get_name(self) -> str:
        """Return the detector name."""
        return self.name


class CompositeDetector(PIIDetector):
    """
    Combines multiple detectors and merges their results.

    This is the main entry point for PII detection, coordinating
    regex, NER, and optional LLM detectors.
    """

    def __init__(self, detectors: List[PIIDetector]):
        """
        Initialize composite detector.

        Args:
            detectors: List of PIIDetector instances to combine
        """
        super().__init__("composite")
        self.detectors = detectors

    def detect(self, text: str) -> List[DetectedEntity]:
        """
        Run all detectors and merge results.

        Args:
            text: Input text to analyze

        Returns:
            Merged and deduplicated list of DetectedEntity objects
        """
        all_entities = []

        for detector in self.detectors:
            try:
                entities = detector.detect(text)
                all_entities.extend(entities)
            except Exception as e:
                # Log error but continue with other detectors
                import structlog
                logger = structlog.get_logger(__name__)
                logger.error(
                    "detector_failed",
                    detector=detector.get_name(),
                    error=str(e),
                )

        # Deduplicate overlapping entities (keep highest confidence)
        return self._deduplicate_entities(all_entities)

    def _deduplicate_entities(
        self,
        entities: List[DetectedEntity],
    ) -> List[DetectedEntity]:
        """
        Remove overlapping entities, keeping the highest confidence ones.

        Args:
            entities: List of potentially overlapping entities

        Returns:
            Deduplicated list
        """
        if not entities:
            return []

        # Sort by confidence (descending) then by span length (descending)
        sorted_entities = sorted(
            entities,
            key=lambda e: (e.confidence, e.end - e.start),
            reverse=True,
        )

        result = []
        for entity in sorted_entities:
            # Check if this entity overlaps with any already selected
            overlaps = False
            for selected in result:
                if self._spans_overlap(entity, selected):
                    overlaps = True
                    break

            if not overlaps:
                result.append(entity)

        return result

    def _spans_overlap(self, e1: DetectedEntity, e2: DetectedEntity) -> bool:
        """Check if two entities have overlapping spans."""
        return not (e1.end <= e2.start or e2.end <= e1.start)

    def supports_entity_type(self, entity_type: PIIType) -> bool:
        """Check if any detector supports this entity type."""
        return any(d.supports_entity_type(entity_type) for d in self.detectors)
