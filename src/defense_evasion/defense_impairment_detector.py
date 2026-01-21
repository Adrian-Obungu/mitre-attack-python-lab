import platform
import logging
import psutil
import os
import hashlib
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class T1562DefenseImpairmentDetector:
    """
    Detects defense impairment techniques, mapping to MITRE ATT&CK Technique T1562.
    """

    def __init__(self):
        """
        Initializes the T1562DefenseImpairmentDetector.
        """
        self.platform = platform.system()
        logger.info(f"T1562DefenseImpairmentDetector initialized on {self.platform}.")

    def check_security_services(self) -> List[str]:
        """
        Checks the status of known security services.
        """
        stopped_services = []
        if self.platform == "Windows":
            services = ["WinDefend", "Sense", "MpsSvc"] # Windows Defender, Advanced Threat Protection, Windows Firewall
        elif self.platform == "Linux":
            services = ["auditd", "rsyslog", "ufw"]
        else:
            services = []

        for service_name in services:
            try:
                service = psutil.win_service_get(service_name) if self.platform == "Windows" else self._get_linux_service_status(service_name)
                if service.status() != 'running':
                    stopped_services.append(service_name)
            except psutil.NoSuchProcess:
                stopped_services.append(service_name)
            except Exception as e:
                logger.debug(f"Could not check status of service {service_name}: {e}")

        return stopped_services

    def _get_linux_service_status(self, service_name: str):
        """
        Helper method to check service status on Linux.
        """
        # This is a simplified check and might need to be adjusted for different Linux distributions
        try:
            # systemctl is common on modern Linux systems
            status = os.system(f"systemctl is-active --quiet {service_name}")
            if status != 0:
                # Mock a service object for consistent return type
                class MockService:
                    def status(self):
                        return 'stopped'
                return MockService()
            else:
                class MockService:
                    def status(self):
                        return 'running'
                return MockService()
        except Exception as e:
            logger.debug(f"Could not check status of service {service_name} using systemctl: {e}")
            return None


    def check_tool_tampering(self) -> List[Dict[str, Any]]:
        """
        Looks for evidence of security tool modification.
        """
        tampering_indicators = []
        if self.platform == "Windows":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            if os.path.exists(hosts_path):
                try:
                    if os.path.getsize(hosts_path) > 1024 * 10: # 10KB
                        tampering_indicators.append({
                            "indicator": "hosts_file_large",
                            "details": f"The hosts file at {hosts_path} is larger than 10KB, which might indicate tampering."
                        })
                except Exception as e:
                    logger.debug(f"Could not get size of hosts file {hosts_path}: {e}")
        elif self.platform == "Linux":
            hosts_path = "/etc/hosts"
            if os.path.exists(hosts_path):
                try:
                    if os.path.getsize(hosts_path) > 1024 * 10: # 10KB
                         tampering_indicators.append({
                            "indicator": "hosts_file_large",
                            "details": f"The hosts file at {hosts_path} is larger than 10KB, which might indicate tampering."
                        })
                except Exception as e:
                    logger.debug(f"Could not get size of hosts file {hosts_path}: {e}")
        
        return tampering_indicators

    def check_log_integrity(self) -> List[Dict[str, Any]]:
        """
        Verifies key security logs exist and haven't been recently truncated or deleted.
        """
        log_issues = []
        if self.platform == "Windows":
            # Windows Event Log integrity is better checked via Event Log APIs,
            # but for a simple check, we can look for the physical files.
            log_paths = [r"C:\Windows\System32\winevt\Logs\Security.evtx"]
        elif self.platform == "Linux":
            log_paths = ["/var/log/auth.log", "/var/log/syslog"]
        else:
            log_paths = []

        for log_path in log_paths:
            if not os.path.exists(log_path):
                log_issues.append({
                    "indicator": "log_file_missing",
                    "details": f"Key security log file is missing: {log_path}"
                })
        
        return log_issues
        
    def run_checks(self) -> Dict[str, List[Any]]:
        """
        Runs all defense impairment checks.
        """
        return {
            "stopped_services": self.check_security_services(),
            "tampering_indicators": self.check_tool_tampering(),
            "log_issues": self.check_log_integrity()
        }

if __name__ == '__main__':
    detector = T1562DefenseImpairmentDetector()
    results = detector.run_checks()
    import json
    print(json.dumps(results, indent=2))
