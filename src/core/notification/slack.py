import requests
import os
import logging
from typing import Dict

from .base import NotificationChannel

logger = logging.getLogger(__name__)

class SlackChannel(NotificationChannel):
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or os.getenv("ALERT_SLACK_WEBHOOK_URL")

    def send(self, alert: Dict) -> bool:
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured. Cannot send alert.")
            return False

        message = {
            "text": f"Security Alert: {alert['severity'].upper()} - {alert['technique_id']}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Security Alert: {alert['severity'].upper()}*"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Technique ID:*\n{alert['technique_id']}"},
                        {"type": "mrkdwn", "text": f"*Timestamp:*\n{alert['timestamp']}"}
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Details:*\n```{alert['details']}```"
                    }
                }
            ]
        }

        try:
            response = requests.post(self.webhook_url, json=message, timeout=10)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False
