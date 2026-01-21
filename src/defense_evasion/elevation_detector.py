import platform
import logging
import psutil
import json
from typing import Dict, List, Any
import os

# Conditional import for winreg
if platform.system() == "Windows":
    import winreg
else:
    winreg = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class T1548ElevationDetector:
    """
    Detects UAC bypass attempts and suspicious elevation patterns, mapping to MITRE ATT&CK Technique T1548.
    """

    def __init__(self):
        """
        Initializes the T1548ElevationDetector.
        """
        self.platform = platform.system()
        logger.info("T1548ElevationDetector initialized.")

    def check_uac_settings(self) -> Dict[str, Any]:
        """
        Checks UAC settings in the registry (Windows-only).
        """
        if self.platform != "Windows" or not winreg:
            return {"uac_enabled": "N/A", "details": "UAC check is only for Windows."}

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\System") as key:
                enable_lua, _ = winreg.QueryValueEx(key, "EnableLUA")
                return {"uac_enabled": enable_lua == 1}

        except FileNotFoundError:
            return {"uac_enabled": "N/A", "details": "UAC registry keys not found."}
        except Exception as e:
            return {"uac_enabled": "N/A", "details": str(e)}

    def scan_auto_elevation_binaries(self) -> List[str]:
        """
        Identifies executables with autoElevate or requireAdministrator in manifests.
        This is a simplified check that looks for known auto-elevating binaries.
        """
        if self.platform != "Windows":
            return []
            
        auto_elevate_binaries = []
        system32_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
        
        known_binaries = ["fodhelper.exe", "eventvwr.exe", "sdclt.exe", "CompMgmtLauncher.exe"]
        
        for binary in known_binaries:
            binary_path = os.path.join(system32_path, binary)
            if os.path.exists(binary_path):
                # A more thorough check would involve parsing the manifest,
                # but that's a complex task. For this lab, we'll just check for existence.
                auto_elevate_binaries.append(binary)
        
        return auto_elevate_binaries

    def detect_suspicious_parent_chains(self) -> List[Dict[str, Any]]:
        """
        Finds processes spawned with unexpected parent-child privilege relationships.
        """
        if self.platform != "Windows":
            return []
        
        findings = []
        # Get all processes and their parents' pids in one go
        proc_map = {p.pid: p.info for p in psutil.process_iter(['name', 'ppid'])}

        for pid, info in proc_map.items():
            try:
                if info['name'].lower() in ["powershell.exe", "cmd.exe"]:
                    parent_pid = info['ppid']
                    if parent_pid in proc_map:
                        parent_name = proc_map[parent_pid]['name']
                        if parent_name.lower() not in ["explorer.exe", "svchost.exe", "services.exe"]:
                            findings.append({
                                "process_name": info['name'],
                                "process_pid": pid,
                                "parent_name": parent_name,
                                "parent_pid": parent_pid,
                                "description": "Suspicious parent process for a shell."
                            })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return findings

    def run_checks(self) -> Dict[str, Any]:
        """
        Runs all elevation checks.
        """
        uac_settings = self.check_uac_settings()
        return {
            "uac_enabled": uac_settings.get("uac_enabled"),
            "auto_elevation_binaries": self.scan_auto_elevation_binaries(),
            "suspicious_chains": self.detect_suspicious_parent_chains()
        }

if __name__ == '__main__':
    detector = T1548ElevationDetector()
    results = detector.run_checks()
    print(json.dumps(results, indent=2))
