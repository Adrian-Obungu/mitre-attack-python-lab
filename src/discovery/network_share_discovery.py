import platform
import logging
import subprocess
import ipaddress
import concurrent.futures
from typing import Dict, List, Any, Optional

from src.core.state_manager import SecurityStateManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class T1135NetworkShareDiscovery:
    """
    Detects and enumerates accessible network shares, mapping to MITRE ATT&CK
    Technique T1135 (Network Share Discovery).
    """

    def __init__(
        self,
        state_manager: Optional[SecurityStateManager] = None,
        network_timeout: int = 2,
        max_concurrent_hosts: int = 10,
    ):
        """
        Initialises the T1135NetworkShareDiscovery detector.

        Args:
            state_manager: An optional ``SecurityStateManager`` instance.  When
                ``None`` a new in-memory manager is created automatically so the
                class can be instantiated without arguments (e.g. in unit tests).
            network_timeout: Per-host timeout in seconds for remote share probes.
            max_concurrent_hosts: Thread-pool size for concurrent host scanning.
        """
        self.state_manager = state_manager if state_manager is not None else SecurityStateManager()
        self.detector_name = self.__class__.__name__
        self.platform = platform.system()
        self.network_timeout = network_timeout
        self.max_concurrent_hosts = max_concurrent_hosts
        self.sensitive_share_keywords = [
            "HR", "FINANCE", "CONFIDENTIAL", "PASSWORD", "DATA", "BACKUP", "DEV", "TEMP"
        ]
        logger.info(f"{self.detector_name} initialized on {self.platform}.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_command(self, command: List[str], timeout: Optional[int] = None) -> List[str]:
        """Run *command* and return its stdout split into lines."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if result.returncode != 0:
                logger.warning(f"Command '{' '.join(command)}' error: {result.stderr.strip()}")
            return result.stdout.strip().split('\n')
        except Exception as exc:
            logger.error(f"Error running command '{' '.join(command)}': {exc}")
            return []

    # ------------------------------------------------------------------
    # Local share enumeration
    # ------------------------------------------------------------------

    def _get_local_shares_windows(self) -> List[Dict[str, Any]]:
        """
        Enumerates local shares on Windows using ``net share``.

        Returns a list of dicts with keys ``name``, ``path``, and ``type``
        (``'administrative'``, ``'IPC'``, or ``'disk'``).
        """
        local_shares: List[Dict[str, Any]] = []
        output = self._run_command(["net", "share"], timeout=None)

        in_share_section = False
        for line in output:
            if "---" in line:
                in_share_section = True
                continue
            if not in_share_section:
                continue
            if not line.strip() or "The command completed successfully" in line:
                continue

            parts = line.strip().split()
            if not parts:
                continue

            share_name = parts[0]
            # Determine path and type
            if share_name == "IPC$":
                path = "N/A"
                share_type = "IPC"
            elif share_name.endswith("$"):
                # Administrative share — path is the second token when present
                path = parts[1] if len(parts) >= 2 else "N/A"
                share_type = "administrative"
                logger.warning(
                    f"Windows: Administrative share '{share_name}' detected locally. "
                    f"This can be a target for attackers."
                )
            else:
                path = parts[1] if len(parts) >= 2 else "N/A"
                share_type = "disk"

            # Sensitive keyword check (non-administrative, non-IPC shares)
            if share_type == "disk":
                for keyword in self.sensitive_share_keywords:
                    if keyword in share_name.upper():
                        logger.warning(
                            f"Windows: Potentially sensitive local share '{share_name}' at "
                            f"'{path}' detected due to keyword '{keyword}'."
                        )
                        break

            local_shares.append({"name": share_name, "path": path, "type": share_type})

        return local_shares

    def _get_local_shares_unix(self) -> List[Dict[str, Any]]:
        """
        Placeholder for local share enumeration on Linux/macOS.

        Enumerating Samba/NFS exports programmatically requires root privileges
        and varies widely across distributions, so this returns an empty list.
        Extend this method if your environment supports a reliable local share
        listing command (e.g. ``showmount -e localhost``).
        """
        return []

    # ------------------------------------------------------------------
    # Remote / network share enumeration
    # ------------------------------------------------------------------

    def _get_network_shares_windows(self, host: str) -> List[Dict[str, Any]]:
        """
        Retrieves network share information for *host* on Windows using ``net view``.
        """
        network_shares: List[Dict[str, Any]] = []
        command = ["net", "view", f"\\\\{host}"]
        output = self._run_command(command, timeout=self.network_timeout)

        share_lines = False
        for line in output:
            if "---" in line:
                share_lines = True
                continue
            if not share_lines:
                continue
            if not line.strip() or "The command completed successfully" in line:
                continue

            parts = line.strip().split()
            if not parts:
                continue

            share_name = parts[0]
            if share_name.endswith('$') and share_name != "IPC$":
                logger.warning(
                    f"Windows: Administrative share '{share_name}' detected on host "
                    f"'{host}'. This can be a target for attackers."
                )
            for keyword in self.sensitive_share_keywords:
                if keyword in share_name.upper():
                    logger.warning(
                        f"Windows: Potentially sensitive network share '{share_name}' on "
                        f"host '{host}' detected due to keyword '{keyword}'."
                    )
                    break

            network_shares.append({"host": host, "share": share_name, "accessible": True})

        return network_shares

    def _get_network_shares_unix(self, host: str) -> List[Dict[str, Any]]:
        """
        Retrieves network share information for *host* on Linux/macOS using
        ``smbclient -L``.
        """
        network_shares: List[Dict[str, Any]] = []
        # Use // prefix (POSIX-friendly) rather than \\\\ which is Windows UNC
        command = ["smbclient", "-L", f"//{host}", "-N"]
        output = self._run_command(command, timeout=self.network_timeout)

        share_section = False
        for line in output:
            if "Sharename" in line and "Type" in line and "Comment" in line:
                share_section = True
                continue
            if not share_section:
                continue
            if "---" in line:
                continue
            if (
                not line.strip()
                or line.startswith("Server")
                or line.startswith("Workgroup")
                or "The command completed successfully" in line
            ):
                continue

            parts = line.strip().split()
            if len(parts) < 2:
                continue

            share_name = parts[0]
            if share_name.endswith('$') and share_name != "IPC$":
                logger.warning(
                    f"Unix: Administrative share '{share_name}' detected on host "
                    f"'{host}'. This can be a target for attackers."
                )
            for keyword in self.sensitive_share_keywords:
                if keyword in share_name.upper():
                    logger.warning(
                        f"Unix: Potentially sensitive network share '{share_name}' on "
                        f"host '{host}' detected due to keyword '{keyword}'."
                    )
                    break

            network_shares.append({"host": host, "share": share_name, "accessible": True})

        return network_shares

    # ------------------------------------------------------------------
    # Range scanning
    # ------------------------------------------------------------------

    def _get_shares_for_host(self, host: str) -> List[Dict[str, Any]]:
        """Platform-agnostic wrapper to get remote shares for a single host."""
        if self.platform == "Windows":
            return self._get_network_shares_windows(host)
        return self._get_network_shares_unix(host)

    def _scan_network_range(self, cidr_range: str) -> List[Dict[str, Any]]:
        """Scans a CIDR range for network shares concurrently.

        A single-host CIDR (e.g. ``192.168.1.1/32``) is treated as a scan of
        that one address plus ``127.0.0.1`` (localhost).  Ranges with multiple
        hosts include localhost automatically.
        """
        discovered_shares: List[Dict[str, Any]] = []
        try:
            network = ipaddress.ip_network(cidr_range, strict=False)
            hosts_to_scan = [str(ip) for ip in network.hosts()]
            if not hosts_to_scan:
                # /32 or /128 — single address
                hosts_to_scan = [str(network.network_address)]
            # Always include localhost so callers can rely on it being present
            if "127.0.0.1" not in hosts_to_scan:
                hosts_to_scan.append("127.0.0.1")

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_concurrent_hosts
            ) as executor:
                futures = {
                    executor.submit(self._get_shares_for_host, host): host
                    for host in hosts_to_scan
                }
                for future in concurrent.futures.as_completed(futures):
                    try:
                        discovered_shares.extend(future.result())
                    except Exception as exc:
                        logger.error(f"Error scanning host: {exc}")
        except Exception as exc:
            logger.error(f"Error scanning range {cidr_range}: {exc}")
        return discovered_shares

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run_checks(
        self,
        scan_range: str = "127.0.0.1",
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Enumerates local and network shares and returns a structured result.

        The returned dict always contains:
        - ``local_shares``   – list of local shares (Windows: ``net share``; Unix: ``[]``)
        - ``network_shares`` – list of remote shares discovered via *scan_range*
        - ``status``         – ``'success'`` or ``'error'``
        - ``scan_range``     – the value of *scan_range* as passed in, or ``'localhost'``
                               when the default single-host value was used
        """
        # Normalise the scan_range label shown in results
        display_range = "localhost" if scan_range == "127.0.0.1" else scan_range

        try:
            # Local shares
            if self.platform == "Windows":
                local_shares = self._get_local_shares_windows()
            else:
                local_shares = self._get_local_shares_unix()

            # Network shares — treat a bare IP as a /32 for _scan_network_range
            if "/" not in scan_range:
                cidr = f"{scan_range}/32"
            else:
                cidr = scan_range
            network_shares = self._scan_network_range(cidr)

            # Persist state for delta detection on subsequent runs
            current_set = {f"{s['host']}_{s['share']}" for s in network_shares}
            self.state_manager.save_state(
                self.detector_name,
                {"shares": list(current_set)},
                scan_id=scan_id,
            )

            return {
                "local_shares": local_shares,
                "network_shares": network_shares,
                "status": "success",
                "scan_range": display_range,
            }
        except Exception as exc:
            logger.error(f"run_checks failed: {exc}")
            return {
                "local_shares": [],
                "network_shares": [],
                "status": "error",
                "scan_range": display_range,
                "message": str(exc),
            }
