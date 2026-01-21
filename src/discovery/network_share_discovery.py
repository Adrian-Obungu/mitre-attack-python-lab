import platform
import logging
import os
import json
import subprocess
import ipaddress
import concurrent.futures
from typing import Dict, List, Any, Optional

from src.core.state_manager import SecurityStateManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class T1135NetworkShareDiscovery:
    """
    Detects and compares accessible network shares over time, mapping to MITRE ATT&CK Technique T1135.
    """

    def __init__(self, state_manager: SecurityStateManager, network_timeout: int = 2, max_concurrent_hosts: int = 10):
        """
        Initializes the T1135NetworkShareDiscovery detector with a state manager.
        """
        self.state_manager = state_manager
        self.detector_name = self.__class__.__name__
        self.platform = platform.system()
        self.network_timeout = network_timeout
        self.max_concurrent_hosts = max_concurrent_hosts
        self.sensitive_share_keywords = ["HR", "FINANCE", "CONFIDENTIAL", "PASSWORD", "DATA", "BACKUP", "DEV", "TEMP"]
        logger.info(f"{self.detector_name} initialized on {self.platform}.")

    def _run_command(self, command: List[str], timeout: Optional[int] = None) -> List[str]:
        """Helper to run shell commands."""
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
            if result.returncode != 0:
                logger.warning(f"Command '{' '.join(command)}' error: {result.stderr.strip()}")
            return result.stdout.strip().split('\n')
        except Exception as e:
            logger.error(f"Error running command '{' '.join(command)}': {e}")
            return []

    def _get_shares_for_host(self, host: str) -> List[Dict[str, Any]]:
        """Platform-agnostic wrapper to get shares for a single host."""
        if self.platform == "Windows":
            return self._get_network_shares_windows(host)
        else: # Linux/macOS
            return self._get_network_shares_unix(host)

    def _get_network_shares_windows(self, host: str) -> List[Dict[str, Any]]:
        """
        Retrieves network share information for a given host on Windows using 'net view'.
        :param host: The target host to scan.
        """
        network_shares = []
        command = ["net", "view", f"\\\\{host}"] # Corrected UNC path
        output = self._run_command(command, timeout=self.network_timeout)

        share_lines = False
        for line in output:
            if "---" in line:
                share_lines = True
                continue
            if share_lines and line.strip() and not "The command completed successfully" in line:
                parts = line.strip().split()
                if len(parts) >= 1:
                    share_name = parts[0]

                    if share_name.endswith('$') and share_name != "IPC$": # Exclude IPC$ from administrative share warnings
                        logger.warning(f"Windows: Administrative share '{share_name}' detected on host '{host}'. This can be a target for attackers.")
                    
                    for keyword in self.sensitive_share_keywords:
                        if keyword in share_name.upper():
                            logger.warning(f"Windows: Potentially sensitive network share '{share_name}' on host '{host}' detected due to keyword '{keyword}'.")
                            break

                    network_shares.append({
                        "host": host,
                        "share": share_name,
                        "accessible": True
                    })
        return network_shares

    def _get_network_shares_unix(self, host: str) -> List[Dict[str, Any]]:
        """
        Retrieves network share information for a given host on Linux/macOS using 'smbclient -L'.
        :param host: The target host to scan.
        """
        network_shares = []
        command = ["smbclient", "-L", f"//{host}", "-N"]
        output = self._run_command(command, timeout=self.network_timeout)
        
        share_section = False
        for line in output:
            if "Sharename" in line and "Type" in line and "Comment" in line:
                share_section = True
                continue
            if share_section and "---" in line:
                continue
            if share_section and line.strip() and not line.startswith("Server") and not line.startswith("Workgroup") and not "The command completed successfully" in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    share_name = parts[0]

                    if share_name.endswith('$') and share_name != "IPC$": # Exclude IPC$ from administrative share warnings
                        logger.warning(f"Unix: Administrative share '{share_name}' detected on host '{host}'. This can be a target for attackers.")

                    for keyword in self.sensitive_share_keywords:
                        if keyword in share_name.upper():
                            logger.warning(f"Unix: Potentially sensitive network share '{share_name}' on host '{host}' detected due to keyword '{keyword}'.")
                            break

                    network_shares.append({
                        "host": host,
                        "share": share_name,
                        "accessible": True
                    })
        return network_shares

    def _scan_network_range(self, cidr_range: str) -> List[Dict[str, Any]]:
        """Scans a CIDR range for network shares concurrently."""
        discovered_shares = []
        try:
            hosts_to_scan = [str(ip) for ip in ipaddress.ip_network(cidr_range).hosts()]
            if not hosts_to_scan and ipaddress.ip_network(cidr_range).num_addresses == 1:
                hosts_to_scan = [str(ipaddress.ip_network(cidr_range).network_address)]

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent_hosts) as executor:
                future_to_host = {executor.submit(self._get_shares_for_host, host): host for host in hosts_to_scan}
                for future in concurrent.futures.as_completed(future_to_host):
                    discovered_shares.extend(future.result())
        except Exception as e:
            logger.error(f"Error scanning range {cidr_range}: {e}")
        return discovered_shares

    def run_checks(self, scan_range: str = "127.0.0.1", scan_id: str = None) -> Dict[str, Any]:
        """
        Runs network share discovery and compares against the previous state.
        """
        current_shares_list = self._scan_network_range(scan_range)
        current_shares_set = {f"{s['host']}_{s['share']}" for s in current_shares_list}

        baseline = self.state_manager.get_latest_state(self.detector_name)
        newly_discovered_shares = []

        if baseline:
            baseline_shares_set = set(baseline.get("shares", []))
            new_shares = current_shares_set - baseline_shares_set
            if new_shares:
                for share_id in new_shares:
                    host, share = share_id.split('_', 1)
                    newly_discovered_shares.append({"host": host, "share": share, "status": "new"})

        # Save the current state for the next run
        self.state_manager.save_state(
            self.detector_name,
            {"shares": list(current_shares_set)},
            scan_id=scan_id
        )

        return {
            "all_discovered_shares": current_shares_list,
            "newly_discovered_shares": newly_discovered_shares,
            "scan_range": scan_range
        }

