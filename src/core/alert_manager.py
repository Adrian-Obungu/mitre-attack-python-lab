from dataclasses import dataclass, field
from enum import Enum
import yaml
import os
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta, UTC

from src.core.state_manager import SecurityStateManager

logger = logging.getLogger(__name__)

class AlertSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AlertRule:
    technique_id: str
    threshold: int
    severity: AlertSeverity
    channels: List[str]
    cooldown_seconds: int = 3600

class AlertManager:
    def __init__(self, state_manager: Optional[SecurityStateManager] = None, test_mode: bool = False):
        self.rules: Dict[str, AlertRule] = self._load_rules()
        self.state_manager = state_manager or SecurityStateManager()
        self.test_mode = test_mode
        self.notification_channels = self._load_notification_channels()

    def _load_rules(self) -> Dict[str, AlertRule]:
        rules_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'alerts', 'rules.yaml')
        try:
            with open(rules_path, 'r') as f:
                raw_rules = yaml.safe_load(f)
                if not raw_rules:
                    return {}
                
                rules = {}
                for rule_data in raw_rules:
                    rule_data['severity'] = AlertSeverity(rule_data['severity'].lower())
                    rules[rule_data['technique_id']] = AlertRule(**rule_data)
                return rules
        except FileNotFoundError:
            logger.warning(f"Alert rules file not found at {rules_path}. No rules will be loaded.")
            return {}
        except Exception as e:
            logger.error(f"Error loading alert rules: {e}")
            return {}

    def _load_notification_channels(self) -> Dict[str, 'NotificationChannel']:
        from src.core.notification.slack import SlackChannel
        from src.core.notification.logfile import LogFileChannel
        from src.core.notification.webhook import WebhookChannel

        channels = {
            "slack": SlackChannel(),
            "logfile": LogFileChannel(),
            "webhook": WebhookChannel(),
        }
        return {name: channel for name, channel in channels.items() if hasattr(channel, 'send')}

    def process_finding(self, finding: Dict) -> Dict:
        """
        Process a security finding, check if it triggers an alert, and send notifications.
        """
        technique_id = finding.get("technique_id")
        rule = self.rules.get(technique_id)

        if not rule:
            return {"should_alert": False, "severity": None, "reason": "No rule for this technique."}

        # Check threshold
        if finding.get("count", 0) < rule.threshold:
            return {"should_alert": False, "severity": None, "reason": "Finding count is below threshold."}
            
        # Check cooldown
        last_alert_timestamp = self.state_manager.get_last_alert_time(technique_id)
        if last_alert_timestamp:
            last_alert_time = datetime.fromtimestamp(last_alert_timestamp, UTC)
            if (datetime.now(UTC) - last_alert_time) < timedelta(seconds=rule.cooldown_seconds):
                return {"should_alert": False, "severity": None, "reason": "Alert is on cooldown."}

        # If all checks pass, create and send alert
        alert = {
            "technique_id": technique_id,
            "severity": rule.severity,
            "details": finding,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        self._send_alert(alert, rule.channels)
        self.state_manager.record_alert(technique_id, datetime.now(UTC).timestamp())

        return {"should_alert": True, "severity": rule.severity}

    def _send_alert(self, alert: Dict, channels: List[str]):
        """
        Send an alert to the specified channels.
        """
        if self.test_mode:
            logger.info(f"[TEST MODE] Alert for {alert['technique_id']} would be sent to: {channels}")
            return

        for channel_name in channels:
            channel = self.notification_channels.get(channel_name)
            if channel:
                try:
                    channel.send(alert)
                except Exception as e:
                    logger.error(f"Failed to send alert via {channel_name}: {e}")
            else:
                logger.warning(f"Notification channel '{channel_name}' not found or configured.")
