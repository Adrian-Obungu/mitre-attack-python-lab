"""
Logon Script Detector
Detects privilege escalation via logon scripts (MITRE T1037)
"""

import os
import sys
import logging
from typing import List, Dict, Any

# Conditional import for winreg - only available on Windows
try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    winreg = None
    WINREG_AVAILABLE = False

logger = logging.getLogger(__name__)

class LogonScriptDetector:
    """Detects logon scripts that could be used for privilege escalation"""
    
    def __init__(self):
        self.technique_id = "T1037"
        self.technique_name = "Boot or Logon Initialization Scripts"
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan for logon scripts in Windows Registry
        
        Returns:
            List of detection findings
        """
        findings = []
        
        if not WINREG_AVAILABLE:
            logger.warning("Windows Registry not available on this system")
            return findings
        
        try:
            # Check common logon script locations
            locations = [
                (winreg.HKEY_CURRENT_USER, r"Environment", "UserInitMprLogonScript"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", None),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", None),
            ]
            
            for hive, key_path, value_name in locations:
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    
                    if value_name:
                        # Check specific value
                        try:
                            value, _ = winreg.QueryValueEx(key, value_name)
                            if value:
                                findings.append({
                                    "technique": self.technique_id,
                                    "name": self.technique_name,
                                    "description": f"Logon script found at {key_path}\\{value_name}",
                                    "risk_level": "MEDIUM",
                                    "evidence": str(value),
                                    "details": {
                                        "hive": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                                        "key": key_path,
                                        "value_name": value_name,
                                        "value": value
                                    }
                                })
                        except FileNotFoundError:
                            pass  # Value doesn't exist, which is normal
                    else:
                        # Check all values in the key
                        i = 0
                        while True:
                            try:
                                value_name, value_data, value_type = winreg.EnumValue(key, i)
                                if value_name and value_data:
                                    # Skip empty/default values
                                    if value_name and not value_name.startswith("("):
                                        findings.append({
                                            "technique": self.technique_id,
                                            "name": "Autorun Execution",
                                            "description": f"Autorun entry found at {key_path}\\{value_name}",
                                            "risk_level": "LOW",
                                            "evidence": f"{value_name}: {value_data}",
                                            "details": {
                                                "hive": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                                                "key": key_path,
                                                "value_name": value_name,
                                                "value": value_data,
                                                "type": value_type
                                            }
                                        })
                                i += 1
                            except OSError:
                                break  # No more values
                    
                    winreg.CloseKey(key)
                    
                except Exception as e:
                    logger.debug(f"Could not access registry key {key_path}: {e}")
        
        except Exception as e:
            logger.error(f"Error scanning for logon scripts: {e}")
        
        return findings

if __name__ == "__main__":
    # Simple test when run directly
    import json
    detector = LogonScriptDetector()
    results = detector.scan()
    print(json.dumps(results, indent=2))
