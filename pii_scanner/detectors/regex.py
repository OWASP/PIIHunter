"""
Regex-based PII detectors.

Fast, deterministic detection of common PII patterns like email,
phone numbers, SSN, credit cards, etc.
"""

import re
from typing import List, Set
from .base import PIIDetector, DetectedEntity, PIIType
import structlog

logger = structlog.get_logger(__name__)


class RegexDetector(PIIDetector):
    """
    Regex-based PII detector with patterns for common identifiers.

    Prioritizes precision over recall to minimize false positives.
    """

    # Email pattern (simplified but effective)
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )

    # Phone number patterns (US and international)
    PHONE_PATTERNS = [
        # US formats: (123) 456-7890, 123-456-7890, 123.456.7890, 1234567890
        re.compile(r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b'),
        # International: +44 20 1234 5678
        re.compile(r'\+[0-9]{1,3}[-.\s]?(?:\([0-9]{1,4}\)|[0-9]{1,4})[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}'),
    ]

    # SSN patterns
    SSN_PATTERNS = [
        # XXX-XX-XXXX
        re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'),
        # XXXXXXXXX (9 digits)
        re.compile(r'\b(?!000|666|9\d{2})(?!00)\d{3}(?!00)\d{2}(?!0000)\d{4}\b'),
    ]

    # Credit card patterns (major brands)
    CREDIT_CARD_PATTERNS = [
        # Visa (13 or 16 digits starting with 4)
        re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'),
        # Mastercard (16 digits starting with 51-55 or 2221-2720)
        re.compile(r'\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b'),
        # Amex (15 digits starting with 34 or 37)
        re.compile(r'\b3[47][0-9]{13}\b'),
        # Discover (16 digits starting with 6011, 622126-622925, 644-649, 65)
        re.compile(r'\b(?:6011|65[0-9]{2}|64[4-9][0-9]|622(?:12[6-9]|1[3-9][0-9]|[2-8][0-9]{2}|9[01][0-9]|92[0-5]))[0-9]{12}\b'),
    ]

    # IP Address (IPv4)
    IP_ADDRESS_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )

    # URL pattern
    URL_PATTERN = re.compile(
        r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)'
    )

    # Date of birth patterns
    DOB_PATTERNS = [
        # MM/DD/YYYY, MM-DD-YYYY, MM.DD.YYYY
        re.compile(r'\b(0[1-9]|1[0-2])[-/.](0[1-9]|[12][0-9]|3[01])[-/.](19|20)\d{2}\b'),
        # YYYY-MM-DD (ISO format)
        re.compile(r'\b(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])\b'),
    ]

    # ZIP code (US)
    ZIP_CODE_PATTERN = re.compile(
        r'\b\d{5}(?:-\d{4})?\b'
    )

    # API Key patterns (generic)
    API_KEY_PATTERNS = [
        re.compile(r'\b[A-Za-z0-9_\-]{32,}\b'),  # Generic long alphanumeric
        re.compile(r'(?i)api[_-]?key["\s:=]+([A-Za-z0-9_\-]{20,})'),
        re.compile(r'(?i)secret[_-]?key["\s:=]+([A-Za-z0-9_\-]{20,})'),
    ]

    # Crypto wallet addresses
    CRYPTO_WALLET_PATTERNS = [
        # Bitcoin
        re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
        # Ethereum
        re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    ]

    def __init__(self, confidence: float = 0.95):
        """
        Initialize regex detector.

        Args:
            confidence: Base confidence score for regex matches (0.0-1.0)
        """
        super().__init__("regex")
        self.confidence = confidence
        self._supported_types = {
            PIIType.EMAIL,
            PIIType.PHONE_NUMBER,
            PIIType.SSN,
            PIIType.CREDIT_CARD,
            PIIType.IP_ADDRESS,
            PIIType.URL,
            PIIType.DATE_OF_BIRTH,
            PIIType.ZIP_CODE,
            PIIType.API_KEY,
            PIIType.CRYPTO_WALLET,
        }

    def detect(self, text: str) -> List[DetectedEntity]:
        """
        Detect PII using regex patterns.

        Args:
            text: Input text to analyze

        Returns:
            List of DetectedEntity objects
        """
        if not text or not isinstance(text, str):
            return []

        entities = []

        # Email
        entities.extend(self._detect_pattern(
            text,
            self.EMAIL_PATTERN,
            PIIType.EMAIL,
            self.confidence,
        ))

        # Phone numbers
        for pattern in self.PHONE_PATTERNS:
            entities.extend(self._detect_pattern(
                text,
                pattern,
                PIIType.PHONE_NUMBER,
                self.confidence,
            ))

        # SSN
        for pattern in self.SSN_PATTERNS:
            entities.extend(self._detect_pattern(
                text,
                pattern,
                PIIType.SSN,
                self.confidence,
                validator=self._validate_ssn,
            ))

        # Credit cards
        for pattern in self.CREDIT_CARD_PATTERNS:
            entities.extend(self._detect_pattern(
                text,
                pattern,
                PIIType.CREDIT_CARD,
                self.confidence,
                validator=self._validate_luhn,
            ))

        # IP addresses
        entities.extend(self._detect_pattern(
            text,
            self.IP_ADDRESS_PATTERN,
            PIIType.IP_ADDRESS,
            self.confidence * 0.8,  # Lower confidence (could be config values)
        ))

        # URLs
        entities.extend(self._detect_pattern(
            text,
            self.URL_PATTERN,
            PIIType.URL,
            self.confidence * 0.7,  # URLs are not always PII
        ))

        # Date of birth
        for pattern in self.DOB_PATTERNS:
            entities.extend(self._detect_pattern(
                text,
                pattern,
                PIIType.DATE_OF_BIRTH,
                self.confidence * 0.8,
            ))

        # ZIP codes
        entities.extend(self._detect_pattern(
            text,
            self.ZIP_CODE_PATTERN,
            PIIType.ZIP_CODE,
            self.confidence * 0.7,
        ))

        # Crypto wallets
        for pattern in self.CRYPTO_WALLET_PATTERNS:
            entities.extend(self._detect_pattern(
                text,
                pattern,
                PIIType.CRYPTO_WALLET,
                self.confidence * 0.85,
            ))

        return entities

    def _detect_pattern(
        self,
        text: str,
        pattern: re.Pattern,
        entity_type: PIIType,
        confidence: float,
        validator=None,
    ) -> List[DetectedEntity]:
        """
        Detect entities using a single pattern.

        Args:
            text: Input text
            pattern: Compiled regex pattern
            entity_type: Type of PII to detect
            confidence: Confidence score
            validator: Optional validation function

        Returns:
            List of DetectedEntity objects
        """
        entities = []

        for match in pattern.finditer(text):
            matched_text = match.group(0)

            # Apply validator if provided
            if validator and not validator(matched_text):
                continue

            entities.append(DetectedEntity(
                entity_type=entity_type,
                confidence=confidence,
                start=match.start(),
                end=match.end(),
                detector_name=self.name,
                text=matched_text,
            ))

        return entities

    def _validate_ssn(self, ssn: str) -> bool:
        """
        Validate SSN format (basic checks).

        Args:
            ssn: SSN string

        Returns:
            True if valid SSN format
        """
        # Remove hyphens
        digits = ssn.replace("-", "")

        if len(digits) != 9:
            return False

        # Invalid area numbers
        area = int(digits[:3])
        if area in (0, 666) or area >= 900:
            return False

        # Invalid group number
        group = int(digits[3:5])
        if group == 0:
            return False

        # Invalid serial number
        serial = int(digits[5:])
        if serial == 0:
            return False

        return True

    def _validate_luhn(self, number: str) -> bool:
        """
        Validate credit card using Luhn algorithm.

        Args:
            number: Credit card number string

        Returns:
            True if passes Luhn check
        """
        # Remove non-digits
        digits = [int(d) for d in number if d.isdigit()]

        if len(digits) < 13 or len(digits) > 19:
            return False

        # Luhn algorithm
        checksum = 0
        reverse_digits = digits[::-1]

        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:  # Every second digit from right
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit

        return checksum % 10 == 0

    def supports_entity_type(self, entity_type: PIIType) -> bool:
        """Check if this detector supports the entity type."""
        return entity_type in self._supported_types
