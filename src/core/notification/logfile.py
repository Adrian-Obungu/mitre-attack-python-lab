import json
import logging
from typing import Dict

from .base import NotificationChannel

logger = logging.getLogger(__name__)

class LogFileChannel(NotificationChannel):
    def __init__(self, log_path: str = "alerts.log"):
        self.log_path = log_path

    def send(self, alert: Dict) -> bool:
        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(alert) + '\n')
            return True
        except Exception as e:
            logger.error(f"Failed to write alert to log file {self.log_path}: {e}")
            return False
