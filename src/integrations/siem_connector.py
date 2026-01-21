from enum import Enum
import os
import json
import logging
import requests
from datetime import datetime, UTC
import time

logger = logging.getLogger(__name__)

class SIEMFormat(str, Enum):
    SPLUNK_CEF = "splunk_cef"
    ELASTIC_ECS = "elastic_ecs"
    QRADAR_LEEF = "qradar_leef"
    GENERIC_JSON = "generic_json"

class SIEMConnector:
    def __init__(self, format_type: SIEMFormat, destination_url: str, test_mode: bool = False):
        self.format_type = format_type
        self.destination_url = destination_url
        self.test_mode = test_mode or os.getenv('SIEM_TEST_MODE', 'False').lower() == 'true'
        
        # Circuit breaker settings
        self.max_failures = 3
        self.retry_delay_seconds = 60
        self._failure_count = 0
        self._last_failure_time = 0

    def send_event(self, event: dict, severity: str) -> bool:
        """
        Formats and sends a security event to the configured SIEM/SOAR platform.
        Includes retry logic and a circuit breaker.
        """
        if self._is_circuit_open():
            logger.warning(f"SIEM circuit breaker is open. Skipping event send to {self.destination_url}")
            return False

        formatted_payload = self._convert_event(event, severity)

        if self.test_mode:
            logger.info(f"[TEST MODE] SIEM event payload for {self.destination_url}:\n{formatted_payload}")
            return True

        try:
            response = requests.post(self.destination_url, data=formatted_payload, headers={'Content-Type': 'application/json'}, timeout=15)
            response.raise_for_status()
            self._reset_circuit_breaker()
            logger.info(f"Successfully sent event to SIEM: {self.destination_url}")
            return True
        except requests.RequestException as e:
            logger.error(f"Failed to send SIEM event to {self.destination_url}: {e}")
            self._increment_failure_count()
            return False

    def _convert_event(self, event: dict, severity: str) -> str:
        """Converts an internal event to the specified SIEM format."""
        # Sanitize event before conversion
        sanitized_event = self._sanitize_event(event)
        
        if self.format_type == SIEMFormat.SPLUNK_CEF:
            return self._to_cef(sanitized_event, severity)
        elif self.format_type == SIEMFormat.ELASTIC_ECS:
            return self._to_ecs(sanitized_event, severity)
        elif self.format_type == SIEMFormat.QRADAR_LEEF:
            return self._to_leef(sanitized_event, severity)
        else: # GENERIC_JSON
            return self._to_generic_json(sanitized_event, severity)

    def _sanitize_event(self, event: dict) -> dict:
        """Removes sensitive or internal-only fields from the event."""
        # Example: remove a field that should not be sent externally
        event.pop('internal_field', None)
        return event

    def _to_cef(self, event: dict, severity: str) -> str:
        """Converts event to Common Event Format (CEF)."""
        # Placeholder implementation
        return f"CEF:0|Gemini Security|MITRE Lab|1.0|{event.get('technique_id', 'N/A')}|{event.get('technique_name', 'N/A')}|{severity}|"

    def _to_ecs(self, event: dict, severity: str) -> str:
        """Converts event to Elastic Common Schema (ECS)."""
        # Placeholder implementation
        return json.dumps({
            "@timestamp": event.get('timestamp', datetime.now(UTC).isoformat()),
            "event": {"category": "intrusion_detection", "severity": severity},
            "rule": {"id": event.get('technique_id'), "name": event.get('technique_name')},
            "details": event.get('details', {})
        })

    def _to_leef(self, event: dict, severity: str) -> str:
        """Converts event to Log Event Extended Format (LEEF)."""
        # Placeholder implementation
        return f"LEEF:2.0|Gemini Security|MITRE Lab|1.0|{event.get('technique_id', 'N/A')}|"

    def _to_generic_json(self, event: dict, severity: str) -> str:
        """Converts event to a generic JSON format."""
        return json.dumps({
            "severity": severity,
            **event
        })

    def _is_circuit_open(self) -> bool:
        """Checks if the circuit breaker is open."""
        if self._failure_count >= self.max_failures:
            if time.time() - self._last_failure_time > self.retry_delay_seconds:
                self._failure_count = 0 # Close the circuit to allow a retry
                return False
            return True
        return False

    def _increment_failure_count(self):
        """Increments the failure count for the circuit breaker."""
        self._failure_count += 1
        self._last_failure_time = time.time()

    def _reset_circuit_breaker(self):
        """Resets the circuit breaker upon a successful send."""
        self._failure_count = 0
        self._last_failure_time = 0
