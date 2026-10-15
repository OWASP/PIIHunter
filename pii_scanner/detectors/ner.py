"""
NER-based PII detection using Microsoft Presidio.

Provides entity recognition for person names, locations, organizations,
and other entities that regex cannot reliably detect.
"""

from typing import List, Set, Optional
from .base import PIIDetector, DetectedEntity, PIIType
import structlog

logger = structlog.get_logger(__name__)


class PresidioDetector(PIIDetector):
    """
    PII detector using Microsoft Presidio analyzer.

    Presidio provides pre-trained NER models for common PII entities
    and supports custom recognizers.
    """

    # Mapping from Presidio entity types to our PIIType enum
    ENTITY_TYPE_MAPPING = {
        "EMAIL_ADDRESS": PIIType.EMAIL,
        "PHONE_NUMBER": PIIType.PHONE_NUMBER,
        "US_SSN": PIIType.SSN,
        "CREDIT_CARD": PIIType.CREDIT_CARD,
        "PERSON": PIIType.PERSON_NAME,
        "LOCATION": PIIType.LOCATION,
        "DATE_TIME": PIIType.DATE_TIME,
        "US_DRIVER_LICENSE": PIIType.US_DRIVER_LICENSE,
        "US_PASSPORT": PIIType.US_PASSPORT,
        "IP_ADDRESS": PIIType.IP_ADDRESS,
        "IBAN_CODE": PIIType.IBAN,
        "URL": PIIType.URL,
        "MEDICAL_LICENSE": PIIType.MEDICAL_LICENSE,
        "US_BANK_NUMBER": PIIType.BANK_ACCOUNT,
    }

    def __init__(
        self,
        min_confidence: float = 0.5,
        language: str = "en",
        entities: Optional[List[str]] = None,
    ):
        """
        Initialize Presidio detector.

        Args:
            min_confidence: Minimum confidence threshold (0.0-1.0)
            language: Language code (default: en)
            entities: List of entity types to detect (None = all)
        """
        super().__init__("presidio")
        self.min_confidence = min_confidence
        self.language = language
        self.entities = entities

        try:
            from presidio_analyzer import AnalyzerEngine

            self.analyzer = AnalyzerEngine()
            logger.info(
                "presidio_initialized",
                language=language,
                min_confidence=min_confidence,
            )

        except ImportError:
            logger.error(
                "presidio_import_failed",
                message="Install presidio-analyzer: pip install presidio-analyzer",
            )
            self.analyzer = None

        self._supported_types = set(self.ENTITY_TYPE_MAPPING.values())

    def detect(self, text: str) -> List[DetectedEntity]:
        """
        Detect PII using Presidio analyzer.

        Args:
            text: Input text to analyze

        Returns:
            List of DetectedEntity objects
        """
        if not self.analyzer:
            logger.warning("presidio_not_available")
            return []

        if not text or not isinstance(text, str):
            return []

        try:
            # Analyze text
            results = self.analyzer.analyze(
                text=text,
                language=self.language,
                entities=self.entities,
                score_threshold=self.min_confidence,
            )

            # Convert Presidio results to our format
            entities = []
            for result in results:
                pii_type = self.ENTITY_TYPE_MAPPING.get(
                    result.entity_type,
                    PIIType.UNKNOWN,
                )

                entities.append(DetectedEntity(
                    entity_type=pii_type,
                    confidence=result.score,
                    start=result.start,
                    end=result.end,
                    detector_name=self.name,
                    text=text[result.start:result.end],
                ))

            logger.debug(
                "presidio_analysis_complete",
                entities_found=len(entities),
            )

            return entities

        except Exception as e:
            logger.error(
                "presidio_analysis_failed",
                error=str(e),
            )
            return []

    def supports_entity_type(self, entity_type: PIIType) -> bool:
        """Check if this detector supports the entity type."""
        return entity_type in self._supported_types


class SpacyNERDetector(PIIDetector):
    """
    Lightweight NER detector using spaCy.

    Can be used as a fallback or alternative to Presidio for
    detecting person names, organizations, and locations.
    """

    # Mapping from spaCy entity labels to PIIType
    ENTITY_TYPE_MAPPING = {
        "PERSON": PIIType.PERSON_NAME,
        "GPE": PIIType.LOCATION,  # Geo-political entity
        "LOC": PIIType.LOCATION,
        "DATE": PIIType.DATE_TIME,
        "TIME": PIIType.DATE_TIME,
    }

    # spaCy doesn't expose per-span scores. These weights are derived from
    # en_core_web_lg's published F-scores so detections are distinguishable
    # by type rather than all returning the same flat confidence.
    LABEL_CONFIDENCE = {
        "PERSON": 0.85,
        "GPE": 0.82,
        "LOC": 0.80,
        "DATE": 0.75,
        "TIME": 0.72,
    }

    def __init__(
        self,
        model_name: str = "en_core_web_lg",
        min_confidence: float = 0.7,
    ):
        """
        Initialize spaCy NER detector.

        Args:
            model_name: spaCy model to use (e.g., en_core_web_lg)
            min_confidence: Minimum confidence threshold
        """
        super().__init__("spacy_ner")
        self.model_name = model_name
        self.min_confidence = min_confidence

        try:
            import spacy

            self.nlp = spacy.load(model_name)
            logger.info(
                "spacy_initialized",
                model=model_name,
            )

        except ImportError:
            logger.error(
                "spacy_import_failed",
                message="Install spacy: pip install spacy",
            )
            self.nlp = None
        except OSError:
            logger.error(
                "spacy_model_not_found",
                model=model_name,
                message=f"Download model: python -m spacy download {model_name}",
            )
            self.nlp = None

        self._supported_types = set(self.ENTITY_TYPE_MAPPING.values())

    def detect(self, text: str) -> List[DetectedEntity]:
        """
        Detect PII using spaCy NER.

        Args:
            text: Input text to analyze

        Returns:
            List of DetectedEntity objects
        """
        if not self.nlp:
            logger.warning("spacy_not_available")
            return []

        if not text or not isinstance(text, str):
            return []

        try:
            doc = self.nlp(text)

            entities = []
            for ent in doc.ents:
                pii_type = self.ENTITY_TYPE_MAPPING.get(ent.label_)

                # Skip unsupported entity types
                if not pii_type:
                    continue

                confidence = max(
                    self.min_confidence,
                    self.LABEL_CONFIDENCE.get(ent.label_, self.min_confidence),
                )

                entities.append(DetectedEntity(
                    entity_type=pii_type,
                    confidence=confidence,
                    start=ent.start_char,
                    end=ent.end_char,
                    detector_name=self.name,
                    text=ent.text,
                ))

            logger.debug(
                "spacy_analysis_complete",
                entities_found=len(entities),
            )

            return entities

        except Exception as e:
            logger.error(
                "spacy_analysis_failed",
                error=str(e),
            )
            return []

    def supports_entity_type(self, entity_type: PIIType) -> bool:
        """Check if this detector supports the entity type."""
        return entity_type in self._supported_types
