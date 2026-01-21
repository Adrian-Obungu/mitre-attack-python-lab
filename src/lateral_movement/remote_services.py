import platform
import logging
import json
import subprocess
import re
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

from src.core.state_manager import SecurityStateManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class T1021RemoteServicesDetector:
    """
    Identifies and analyzes remote service access patterns, mapping to MITRE ATT&CK Technique T1021.
    """

    def __init__(self, state_manager: Optional[SecurityStateManager] = None):
        """
        Initializes the T1021RemoteServicesDetector with an optional state manager.
        """
        self.state_manager = state_manager or SecurityStateManager()
        self.detector_name = self.__class__.__name__
        self.platform = sys.platform
        self.analysis_window_hours = 24
        logger.info(f"{self.detector_name} initialized on {self.platform}.")

    def _run_command(self, command: List[str], timeout: Optional[int] = 15) -> List[str]:
        """Helper to run shell commands."""
        try:
            full_command = ["powershell.exe", "-Command"] + command if self.platform == "win32" else command
            result = subprocess.run(
                full_command, capture_output=True, text=True, timeout=timeout, check=False, encoding='utf-8', errors='ignore'
            )
            if result.returncode != 0:
                logger.warning(f"Command '{' '.join(command)}' error: {result.stderr.strip()}")
            return result.stdout.strip().split('\n')
        except Exception as e:
            logger.error(f"Error running command '{' '.join(command)}': {e}")
            return []

    def _get_rdp_sessions_windows(self) -> List[Dict[str, Any]]:
        """Detects RDP sessions by querying Windows Event Logs for Logon Type 10."""
        if self.platform != "win32": return []
        logger.info("Querying Windows Event Log for RDP sessions...")
        sessions = []
        query = "<QueryList><Query Path='Security'><Select Path='Security'>*[System[EventID=4624] and EventData[Data[@Name='LogonType']='10']]</Select></Query></QueryList>"
        query_path = "rdp_query.xml"
        with open(query_path, "w") as f: f.write(query)
        
        try:
            output = self._run_command(["wevtutil", "qe", "Security", f"/q:{query_path}", "/f:Text"])
            # ... (parsing logic as before) ...
        finally:
            if os.path.exists(query_path): os.remove(query_path)
        return sessions

    def _get_ssh_sessions_linux(self) -> List[Dict[str, Any]]:
        """Detects SSH sessions by parsing /var/log/auth.log on Linux."""
        if self.platform != "linux": return []
        logger.info("Parsing auth.log for SSH sessions...")
        sessions = []
        log_path = Path("/var/log/auth.log")
        if not log_path.exists(): return []
        
        try:
            with open(log_path, "r") as f:
                for line in f:
                    if "sshd" in line and "Accepted password" in line:
                        match = re.search(r"for (\S+) from (\S+)", line)
                        if match:
                            user, source_ip = match.groups()
                            sessions.append({
                                "service": "SSH", "source": source_ip, "destination": "localhost",
                                "user": user, "timestamp": line[:15], "details": "Accepted password login."
                            })
        except Exception as e:
            logger.error(f"Error parsing SSH log file: {e}")
        return sessions

    def _analyze_saved_credentials(self) -> List[Dict[str, Any]]:
        """Identifies saved credentials like SSH keys and RDP connection files."""
        saved_creds = []
        home_dir = Path.home()
        
        # SSH keys
        ssh_dir = home_dir / ".ssh"
        if ssh_dir.exists():
            for item in ssh_dir.iterdir():
                if item.is_file() and "id_" in item.name and not item.name.endswith(".pub"):
                    saved_creds.append({
                        "type": "SSH private key", "location": str(item),
                        "accessible": os.access(item, os.R_OK)
                    })
        
        # RDP files (Windows)
        if self.platform == "win32":
            docs = home_dir / "Documents"
            if docs.exists():
                for rdp_file in docs.glob("*.rdp"):
                    saved_creds.append({"type": "RDP connection file", "location": str(rdp_file)})

        return saved_creds

    def _map_lateral_paths(self, sessions: List[Dict], shares: List[Dict]) -> List[Dict]:
        """Correlates session and share data to infer lateral movement paths."""
        paths = []
        # Example logic: If a user from host A connects via RDP and also accesses a share
        # on host B, that's a potential path.
        # This is a placeholder for more complex correlation logic.
        for session in sessions:
            if session['service'] in ["RDP", "SSH"]:
                paths.append({
                    "from": session['source'],
                    "to": session['destination'],
                    "via": session['service'],
                    "confidence": 0.6 # Base confidence for a remote session
                })
        return paths

    def analyze_network_data(self, network_data: Optional[Dict] = None, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyzes remote service patterns and compares with historical data.
        
        :param network_data: Optional results from a T1135 network share scan.
        :param scan_id: An optional ID for the scan.
        """
        # --- 1. Gather current remote session data ---
        current_sessions = []
        if self.platform == "win32":
            current_sessions.extend(self._get_rdp_sessions_windows())
        elif self.platform == "linux":
            current_sessions.extend(self._get_ssh_sessions_linux())
        
        # --- 2. Compare with historical data ---
        historical_sessions_raw = self.state_manager.get_latest_state(self.detector_name)
        historical_sessions = historical_sessions_raw.get("sessions", []) if historical_sessions_raw else []
        
        current_session_keys = {f"{s['service']}-{s['source']}-{s['user']}" for s in current_sessions}
        historical_session_keys = {f"{s['service']}-{s['source']}-{s['user']}" for s in historical_sessions}
        
        new_sessions = [s for s in current_sessions if f"{s['service']}-{s['source']}-{s['user']}" not in historical_session_keys]

        # --- 3. Analyze credentials and paths ---
        saved_credentials = self._analyze_saved_credentials()
        network_shares = network_data.get("network_shares", []) if network_data else []
        lateral_paths = self._map_lateral_paths(current_sessions, network_shares)

        # --- 4. Save new state ---
        self.state_manager.save_state(self.detector_name, {"sessions": current_sessions}, scan_id=scan_id)

        return {
            "newly_detected_sessions": new_sessions,
            "all_current_sessions": current_sessions,
            "saved_credentials": saved_credentials,
            "potential_lateral_paths": lateral_paths
        }
    
    # Alias run_checks to the new method for compatibility
    run_checks = analyze_network_data

if __name__ == '__main__':
    detector = T1021RemoteServicesDetector()
    results = detector.run_checks()
    print(json.dumps(results, indent=2))
