from abc import ABC, abstractmethod
from typing import Dict

class NotificationChannel(ABC):
    @abstractmethod
    def send(self, alert: Dict) -> bool:
        """
        Send an alert.
        
        :param alert: A dictionary containing the alert details.
        :return: True if the alert was sent successfully, False otherwise.
        """
        pass
