import platform
import logging
import os
import stat
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

from src.core.state_manager import SecurityStateManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class T1550AlternateAuthDetector:
    """
    Safely identifies stored authentication material that could be abused for lateral movement,
    without exposing the actual credentials. Maps to MITRE ATT&CK Technique T1550.
    """

    def __init__(self, state_manager: Optional[SecurityStateManager] = None):
        """
        Initializes the T1550AlternateAuthDetector.
        """
        self.state_manager = state_manager or SecurityStateManager()
        self.detector_name = self.__class__.__name__
        self.platform = platform.system()
        self.project_root = Path.cwd()
        logger.info(f"{self.detector_name} initialized on {self.platform}.")

    def _mask_path(self, path: Path) -> str:
        """Masks a path if it is outside the project directory."""
        try:
            if self.project_root in path.parents:
                return f"./{path.relative_to(self.project_root)}"
            else:
                # Mask parts of the path for privacy
                return f"{path.parts[0]}/.../{path.name}"
        except (ValueError, IndexError):
            return str(path)

    def _get_permissions(self, path: Path) -> str:
        """Gets file permissions in octal format (e.g., '600')."""
        if not os.access(path, os.R_OK):
            return "inaccessible"
        try:
            return stat.S_IMODE(path.stat().st_mode)
        except (PermissionError, FileNotFoundError):
            return "error"

    def _scan_credential_file_locations(self) -> List[Dict[str, Any]]:
        """Scans for common file-based credential storage locations."""
        findings = []
        home = Path.home()
        
        locations = {
            "SSH Keys": [home / ".ssh" / "id_rsa", home / ".ssh" / "id_dsa"],
            "AWS Credentials": [home / ".aws" / "credentials"],
            "GCP Credentials": [home / ".config" / "gcloud" / "application_default_credentials.json"],
        }
        
        for cred_type, paths in locations.items():
            for path in paths:
                if path.exists() and path.is_file():
                    permissions = self._get_permissions(path)
                    findings.append({
                        "type": "file_based_credential",
                        "description": f"{cred_type} file found.",
                        "location_masked": self._mask_path(path),
                        "permissions": permissions,
                        "risk_level": "medium" if "600" in str(permissions) else "high"
                    })
        return findings

    def _scan_config_files(self, scan_path: Path) -> List[Dict[str, Any]]:
        """Scans for common config files that may contain secrets."""
        findings = []
        config_patterns = [".env", "config.json", "credentials.json", "*.pem", "web.config"]
        
        for pattern in config_patterns:
            for path in scan_path.rglob(pattern):
                if path.is_file():
                    findings.append({
                        "type": "config_file_risk",
                        "description": f"Potential secret-bearing config file '{path.name}' found.",
                        "location": self._mask_path(path),
                        "permissions": self._get_permissions(path),
                        "risk_level": "high"
                    })
        return findings

    def _check_system_caches(self) -> List[Dict[str, Any]]:
        """Identifies the presence of system-level credential caches."""
        findings = []
        if self.platform == "Linux" or self.platform == "Darwin":
            try:
                result = subprocess.run(["klist"], capture_output=True, text=True, check=False)
                if result.returncode == 0 and "Ticket cache" in result.stdout:
                    findings.append({
                        "type": "credential_cache_present",
                        "description": "Kerberos ticket cache detected.",
                        "evidence": "`klist` command returned active tickets.",
                        "risk_level": "low"
                    })
            except FileNotFoundError:
                pass # klist not installed

        elif self.platform == "Windows":
            cred_path = Path(os.environ.get("APPDATA", "")) / "../Local/Microsoft/Credentials"
            if cred_path.exists():
                findings.append({
                    "type": "credential_cache_present",
                    "description": "Windows Credential Manager folder exists.",
                    "evidence": f"Folder found at {self._mask_path(cred_path)}",
                    "risk_level": "low"
                })
        return findings

    def run_checks(self, scan_path: str = ".") -> Dict[str, Any]:
        """
        Runs all alternate auth material checks.
        :param scan_path: The local directory path to scan for config files.
        """
        all_findings = []
        all_findings.extend(self._scan_credential_file_locations())
        all_findings.extend(self._scan_config_files(Path(scan_path)))
        all_findings.extend(self._check_system_caches())
        
        high_risk_count = len([f for f in all_findings if f['risk_level'] == 'high'])

        return {
            "findings": all_findings,
            "summary": {
                "total_findings": len(all_findings),
                "high_risk_findings": high_risk_count
            }
        }

if __name__ == '__main__':
    detector = T1550AlternateAuthDetector()
    results = detector.run_checks(scan_path=".")
    print(json.dumps(results, indent=2))
