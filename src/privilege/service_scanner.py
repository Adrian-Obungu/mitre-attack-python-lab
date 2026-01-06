import os
import logging
import subprocess
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Conditional import for winreg - only available on Windows
try:
    import winreg
except ImportError:
    winreg = None
    logger.warning("winreg module not available. Registry-based service checks might be limited.")


class ServiceScanner:
    """
    Scans for Windows Service Misconfigurations (T1543.003).
    """
    def __init__(self):
        self.findings = []

    def _is_windows(self) -> bool:
        """Checks if the current operating system is Windows."""
        return os.name == 'nt'

    def _get_service_info_from_wmic(self) -> List[Dict[str, str]]:
        """
        Retrieves basic service information using wmic.
        Returns a list of dictionaries with 'Name', 'PathName', 'StartMode', 'State'.
        """
        if not self._is_windows():
            return []

        command = 'wmic service get Name,PathName,StartMode,State /format:list'
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                shell=True
            )
            
            services_raw = result.stdout.strip().split('\n\n')
            parsed_services = []
            for service_block in services_raw:
                if not service_block.strip():
                    continue
                service_data = {}
                for line in service_block.split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        service_data[key.strip()] = value.strip()
                if service_data:
                    parsed_services.append(service_data)
            return parsed_services
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running WMIC command: {e.stderr}")
            return []
        except Exception as e:
            logger.error(f"Failed to parse WMIC service output: {e}")
            return []

    def _check_unquoted_service_paths(self, service: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """
        Checks for unquoted service paths that can lead to DLL hijacking.
        """
        path_name = service.get('PathName', '')
        if not path_name:
            return None

        # Service paths with spaces AND not enclosed in quotes are vulnerable
        if ' ' in path_name and not (path_name.startswith('"') and path_name.endswith('"')):
            return {
                "type": "Unquoted Service Path",
                "description": f"Service '{service.get('Name')}' has an unquoted path containing spaces. This can lead to privilege escalation via DLL hijacking.",
                "evidence": f"Path: {path_name}",
                "risk_level": "HIGH",
                "mitigation": f"Quote the service path for '{service.get('Name')}' in the registry (ImagePath value)."
            }
        return None

    def _check_weak_permissions_on_service_path(self, service: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """
        Placeholder: Checks for weak permissions on the service executable path.
        This is complex as it requires querying ACLs (icacls) or using Python libraries
        like `pywin32` (which is an external dependency we want to avoid for now).
        For now, this will be a mock finding.
        """
        path_name = service.get('PathName', '').strip('"') # Remove quotes for path check
        if not path_name or not os.path.exists(path_name):
            return None
        
        # This is a placeholder. Real implementation needs `icacls` parsing or `pywin32`.
        # Example: check if path_name is in C:\Program Files\ and has a specific non-admin group write access.
        
        # Mock finding for demonstration purposes
        if "program files" in path_name.lower() and "unsecured" in service.get('Name', '').lower():
            return {
                "type": "Weak Permissions on Service Executable",
                "description": f"Service '{service.get('Name')}' executable at '{path_name}' might have weak permissions (placeholder).",
                "evidence": f"Path: {path_name}",
                "risk_level": "MEDIUM",
                "mitigation": "Review NTFS permissions on the service executable and its parent directories. Ensure only SYSTEM and Administrators have write access."
            }
        return None


    def run_all_checks(self) -> List[Dict[str, Any]]:
        """
        Runs all configured service misconfiguration checks.
        """
        if not self._is_windows():
            logger.info("Skipping service misconfiguration checks: Not on Windows.")
            return []

        all_findings = []
        services = self._get_service_info_from_wmic()

        for service in services:
            # Check for unquoted service paths
            finding = self._check_unquoted_service_paths(service)
            if finding:
                all_findings.append(finding)
            
            # Check for weak permissions on service path (placeholder)
            finding = self._check_weak_permissions_on_service_path(service)
            if finding:
                all_findings.append(finding)

        if not all_findings:
            logger.info("No service misconfigurations detected.")
        return all_findings
