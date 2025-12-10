"""
LLM-based PII classifier for free-text columns.

WARNING: This should ONLY be used with self-hosted/private LLM endpoints.
DO NOT send real production PII to public APIs.
"""

from typing import List, Optional, Dict, Any
import json
from .base import PIIDetector, DetectedEntity, PIIType
import structlog

logger = structlog.get_logger(__name__)


class LLMClassifier(PIIDetector):
    """
    LLM-based PII classifier for ambiguous text.

    This detector is designed for free-form text columns where
    regex and NER may not be sufficient (e.g., notes, comments, descriptions).

    CRITICAL: Only use with self-hosted or private LLM endpoints.
    """

    CLASSIFICATION_PROMPT = """You are a privacy analysis tool. Analyze the following text and identify any Personally Identifiable Information (PII).

Text to analyze:
{text}

Respond with a JSON object containing:
{{
  "contains_pii": true/false,
  "entities": [
    {{"type": "EMAIL", "confidence": 0.95}},
    {{"type": "PERSON_NAME", "confidence": 0.85}}
  ]
}}

Supported PII types: EMAIL, PHONE_NUMBER, SSN, PERSON_NAME, ADDRESS, DATE_OF_BIRTH, CREDIT_CARD, LOCATION

Only include entities you are confident about (>0.5 confidence). Respond with valid JSON only."""

    def __init__(
        self,
        endpoint_url: str,
        api_key: Optional[str] = None,
        model: str = "llama-2-7b",
        min_confidence: float = 0.6,
        max_text_length: int = 500,
        timeout: int = 10,
    ):
        """
        Initialize LLM classifier.

        Args:
            endpoint_url: Private LLM endpoint URL
            api_key: API key for authentication (if required)
            model: Model name/identifier
            min_confidence: Minimum confidence threshold
            max_text_length: Max characters to send to LLM
            timeout: Request timeout in seconds

        Raises:
            ValueError: If endpoint_url appears to be a public service
        """
        super().__init__("llm_classifier")

        # Safety check: prevent use of public APIs
        if self._is_public_endpoint(endpoint_url):
            raise ValueError(
                f"LLM endpoint appears to be public: {endpoint_url}. "
                "Only self-hosted/private endpoints are allowed for PII scanning."
            )

        self.endpoint_url = endpoint_url
        self.api_key = api_key
        self.model = model
        self.min_confidence = min_confidence
        self.max_text_length = max_text_length
        self.timeout = timeout

        logger.warning(
            "llm_classifier_initialized",
            endpoint=endpoint_url,
            model=model,
            message="Ensure this endpoint is self-hosted and secure!",
        )

        self._supported_types = {
            PIIType.EMAIL,
            PIIType.PHONE_NUMBER,
            PIIType.SSN,
            PIIType.PERSON_NAME,
            PIIType.ADDRESS,
            PIIType.DATE_OF_BIRTH,
            PIIType.CREDIT_CARD,
            PIIType.LOCATION,
        }

    def _is_public_endpoint(self, url: str) -> bool:
        """
        Check if URL appears to be a public API endpoint.

        Args:
            url: Endpoint URL

        Returns:
            True if URL looks like a public service
        """
        public_domains = [
            "api.openai.com",
            "api.anthropic.com",
            "api.cohere.ai",
            "api.together.xyz",
            "huggingface.co",
            "replicate.com",
        ]

        url_lower = url.lower()
        return any(domain in url_lower for domain in public_domains)

    def detect(self, text: str) -> List[DetectedEntity]:
        """
        Classify text using LLM.

        Args:
            text: Input text to analyze

        Returns:
            List of DetectedEntity objects
        """
        if not text or not isinstance(text, str):
            return []

        # Truncate text to max length
        if len(text) > self.max_text_length:
            text = text[:self.max_text_length]
            logger.debug(
                "text_truncated",
                original_length=len(text),
                truncated_length=self.max_text_length,
            )

        try:
            response = self._call_llm(text)
            entities = self._parse_llm_response(response, text)

            logger.debug(
                "llm_classification_complete",
                entities_found=len(entities),
            )

            return entities

        except Exception as e:
            logger.error(
                "llm_classification_failed",
                error=str(e),
            )
            return []

    def _call_llm(self, text: str) -> Dict[str, Any]:
        """
        Call the LLM endpoint.

        Args:
            text: Text to classify

        Returns:
            Parsed JSON response from LLM

        Raises:
            Exception: If the request fails
        """
        import requests

        prompt = self.CLASSIFICATION_PROMPT.format(text=text)

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,  # Low temperature for consistency
            "max_tokens": 500,
        }

        response = requests.post(
            self.endpoint_url,
            headers=headers,
            json=payload,
            timeout=self.timeout,
        )

        response.raise_for_status()

        result = response.json()

        # Extract content from response (format varies by endpoint)
        content = result.get("choices", [{}])[0].get("message", {}).get("content", "")

        # Parse JSON from content
        return json.loads(content)

    def _parse_llm_response(
        self,
        response: Dict[str, Any],
        original_text: str,
    ) -> List[DetectedEntity]:
        """
        Parse LLM JSON response into DetectedEntity objects.

        Args:
            response: Parsed JSON response
            original_text: Original text that was classified

        Returns:
            List of DetectedEntity objects
        """
        entities = []

        if not response.get("contains_pii", False):
            return entities

        for entity_data in response.get("entities", []):
            try:
                entity_type_str = entity_data.get("type", "UNKNOWN")
                confidence = float(entity_data.get("confidence", 0.5))

                # Skip low confidence entities
                if confidence < self.min_confidence:
                    continue

                # Map string to PIIType enum
                try:
                    entity_type = PIIType[entity_type_str]
                except KeyError:
                    logger.warning(
                        "unknown_entity_type_from_llm",
                        type=entity_type_str,
                    )
                    entity_type = PIIType.UNKNOWN

                # LLM doesn't provide exact spans, so we mark entire text
                entities.append(DetectedEntity(
                    entity_type=entity_type,
                    confidence=confidence,
                    start=0,
                    end=len(original_text),
                    detector_name=self.name,
                    text=None,  # Don't store full text
                ))

            except Exception as e:
                logger.warning(
                    "failed_to_parse_entity_from_llm",
                    entity_data=entity_data,
                    error=str(e),
                )
                continue

        return entities

    def supports_entity_type(self, entity_type: PIIType) -> bool:
        """Check if this detector supports the entity type."""
        return entity_type in self._supported_types
