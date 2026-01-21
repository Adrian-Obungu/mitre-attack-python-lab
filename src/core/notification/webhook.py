import requests
import os
import logging
from typing import Dict

from .base import NotificationChannel

logger = logging.getLogger(__name__)

class WebhookChannel(NotificationChannel):
    def __init__(self, url: str = None):
        self.url = url or os.getenv("ALERT_WEBHOOK_URL")

    def send(self, alert: Dict) -> bool:
        if not self.url:
            logger.warning("Webhook URL not configured. Cannot send alert.")
            return False

        try:
            response = requests.post(self.url, json=alert, timeout=10)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False
