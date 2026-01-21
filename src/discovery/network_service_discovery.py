import platform
import logging
import os
import json
import subprocess
import time
import re
import socket
import ipaddress
import random
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class T1046NetworkServiceDiscovery:
    """
    Discovers active network services, listening ports, and potential vulnerabilities,
    mapping to MITRE ATT&CK Technique T1046.
    """

    def __init__(self,
                 allowed_scan_ranges: Optional[List[str]] = None,
                 max_ports_per_scan: int = 100,
                 port_timeout: int = 1,
                 rate_limit_per_second: int = 10):
        """
        Initializes the T1046NetworkServiceDiscovery detector.
        """
        self.platform = platform.system()
        self.allowed_scan_ranges = allowed_scan_ranges if allowed_scan_ranges is not None else ['127.0.0.1', 'localhost', '192.168.1.0/24']
        self.max_ports_per_scan = max_ports_per_scan
        self.port_timeout = port_timeout
        self.rate_limit_per_second = rate_limit_per_second
        logger.info(f"T1046NetworkServiceDiscovery initialized on {self.platform}.")

    def _run_command(self, command: List[str], timeout: int = None) -> List[str]:
        """Helper to run shell commands and return output lines."""
        try:
            full_command = ["powershell.exe", "-Command"] + command if self.platform == "Windows" else command
            result = subprocess.run(
                full_command, capture_output=True, text=True, timeout=timeout, check=False
            )
            if result.returncode != 0:
                logger.debug(f"Command '{' '.join(command)}' exited with error {result.returncode}: {result.stderr.strip()}")
            return result.stdout.strip().split('\n')
        except subprocess.TimeoutExpired:
            logger.warning(f"Command '{' '.join(command)}' timed out.")
            return []
        except Exception as e:
            logger.error(f"Error running command '{' '.join(command)}': {e}")
            return []

    def _validate_scan_range(self, target_range: str) -> bool:
        """Validates if a target range is within the allowed scan ranges."""
        try:
            target_net = ipaddress.ip_network(target_range, strict=False)
            for allowed in self.allowed_scan_ranges:
                allowed_net = ipaddress.ip_network(allowed, strict=False)
                if target_net.subnet_of(allowed_net):
                    logger.info(f"Target range {target_range} is within allowed range {allowed}.")
                    return True
        except ValueError:
            if target_range in self.allowed_scan_ranges:
                logger.info(f"Target {target_range} is in allowed list.")
                return True
        logger.warning(f"Scan range '{target_range}' is not permitted. Skipping.")
        return False

    def _scan_network_ports(self, target_ranges: List[str], max_ports: int = 100) -> List[Dict[str, Any]]:
        """Safely scans allowed network ranges for open ports with rate limiting."""
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5900, 8080]
        ports_to_scan = common_ports + random.sample(range(1, 1024), k=min(max_ports - len(common_ports), 1024-len(common_ports)))

        ports_scanned_this_second = 0
        second_start_time = time.time()

        for target in target_ranges:
            if not self._validate_scan_range(target):
                continue
            
            try:
                network = ipaddress.ip_network(target, strict=False)
                hosts = [str(ip) for ip in network.hosts()] or [str(network.network_address)]
            except ValueError:
                hosts = [target]

            for host in hosts:
                logger.info(f"Scanning host: {host}")
                for port in ports_to_scan:
                    if time.time() - second_start_time > 1.0:
                        second_start_time = time.time()
                        ports_scanned_this_second = 0
                    
                    if ports_scanned_this_second >= self.rate_limit_per_second:
                        time.sleep(1.0 - (time.time() - second_start_time))
                        second_start_time = time.time()
                        ports_scanned_this_second = 0

                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(self.port_timeout)
                        if sock.connect_ex((host, port)) == 0:
                            logger.info(f"Port {port} is open on {host}")
                            open_ports.append({"host": host, "port": port})
                    ports_scanned_this_second += 1
        return open_ports

    def _fingerprint_service(self, host: str, port: int) -> Dict[str, Any]:
        """Identifies a service on a port using mappings and banner grabbing."""
        common_ports = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3389: "RDP"}
        service_info = {
            "host": host, "port": port,
            "service_name": common_ports.get(port, "Unknown"),
            "banner": "", "is_privileged_port": port < 1024
        }
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((host, port))
                if port in [80, 8080]:
                    s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                banner = s.recv(1024)
                service_info["banner"] = banner.decode('utf-8', 'ignore').strip()
        except Exception:
            pass
        return service_info

    def _identify_privileged_services(self, services_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Flags services on privileged ports or running as high-privilege users."""
        privileged = []
        for service in services_list:
            if service.get("is_privileged_port"):
                service["is_privileged_service"] = True
            process = service.get("process", "").lower()
            if "system" in process or "root" in process:
                 service["is_privileged_service"] = True
            if service.get("is_privileged_service"):
                privileged.append(service)
        return privileged

    def _detect_vulnerable_services(self, services_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identifies potentially vulnerable services based on heuristics."""
        vulnerable = []
        patterns = {"Telnet": "Unencrypted communication.", "SSH": "Check banner for old versions."}
        for service in services_list:
            name = service.get("service_name", "Unknown")
            banner = service.get("banner", "").lower()
            if name in patterns:
                service["vulnerability_reason"] = patterns[name]
                if name == "SSH" and "openssh" in banner:
                    match = re.search(r"openssh_([0-9]+\.[0-9]+)", banner)
                    if match and float(match.group(1)) < 7.7:
                        service["vulnerability_reason"] += f" Old version {match.group(1)} detected."
                vulnerable.append(service)
        return vulnerable
    
    def _get_local_services_windows(self) -> List[Dict[str, str]]:
        """
        Identifies active network services and listening ports on Windows using 'netstat -ano'.
        """
        local_services = []
        # netstat -ano output columns: Proto Local_Address Foreign_Address State PID
        output = self._run_command(["netstat", "-ano"], timeout=self.port_timeout * 5) # Increased timeout for netstat

        header_found = False
        for line in output:
            line = line.strip()
            if line.startswith("Proto") and "Local Address" in line and "State" in line and "PID" in line:
                header_found = True
                continue
            if not header_found or not line:
                continue
            
            parts = line.split()
            protocol = parts[0].lower()
            local_address_port = parts[1]
            
            # Handle UDP lines where 'State' column is often missing
            if protocol == "udp" and len(parts) >= 4: # Proto, Local Address, Foreign Address, PID
                state = "" # No state for UDP in netstat -ano output
                pid = parts[3].strip()
            elif len(parts) >= 5: # Proto, Local Address, Foreign Address, State, PID
                state = parts[3].lower()
                pid = parts[4].strip()
            else:
                continue # Skip lines that don't conform to expected structure

            # Resolve process name from PID
            process_name = "unknown"
            try:
                tasklist_output = self._run_command(["tasklist", "/svc", "/FI", f"PID eq {pid}"], timeout=self.port_timeout)
                for t_line in tasklist_output:
                    if t_line.startswith("Image Name") or t_line.startswith("====="): # Skip header and separator
                        continue
                    # Use simple split for now, if re.split was causing issues
                    t_parts = t_line.split() 
                    # Assuming tasklist output: Image Name (0), PID (1)
                    if len(t_parts) >= 2 and t_parts[1].strip() == pid: # Ensure pid from tasklist is numeric
                        process_name = t_parts[0]
                        break
            except Exception as e:
                logger.debug(f"Could not resolve process name for PID {pid}: {e}")
            
            local_services.append({
                "protocol": protocol,
                "local_address": local_address_port,
                "state": state,
                "process": process_name
            })
        return local_services

    def _get_local_services_linux(self) -> List[Dict[str, str]]:
        """
        Identifies active network services and listening ports on Linux using 'ss -tulnp'.
        """
        local_services = []
        output = self._run_command(["ss", "-tulnp"], timeout=self.port_timeout * 5)

        header_found = False
        for line in output:
            line = line.strip()
            if not line: # Skip empty lines
                continue
            if line.startswith("Netid") and "Local Address:Port" in line: # Simplified header check
                header_found = True
                continue
            if not header_found: # Skip lines until header is found
                continue

            # Example line: tcp    LISTEN     0      128    0.0.0.0:22             0.0.0.0:*    users:(("sshd",pid=839,fd=3)))
            parts = re.split(r'\s+', line) # Use regex split to handle varying whitespace
            if len(parts) >= 5: # Netid, State, Recv-Q, Send-Q, Local_Address:Port (minimum 5 parts for data)
                protocol = parts[0].lower() # tcp, udp
                state = parts[1].lower()
                local_address_port = parts[4] # 0.0.0.0:22

                process_name = "unknown"
                process_info_found = False
                # Search for process info from Peer Address column onwards (parts[5] and later)
                # The 'Process' info is usually the last part of the line.
                for i in range(len(parts) -1, 4, -1): # Search backwards from the end, starting before peer address.
                    if "users:((" in parts[i]:
                        process_info = parts[i]
                        process_info_found = True
                        break
                
                if process_info_found:
                    match = re.search(r'"(.*?)"', process_info)
                    if match:
                        process_name = match.group(1)
                
                local_services.append({
                    "protocol": protocol,
                    "local_address": local_address_port,
                    "state": state,
                    "process": process_name
                })
        return local_services

    def run_checks(self, network_scan: bool = False) -> Dict[str, Any]:
        """Runs all network service discovery checks."""
        start_time = time.perf_counter()
        results: Dict[str, Any] = {
            "local_services": [], "network_services": [],
            "privileged_services": [], "vulnerable_services": [],
            "status": "success"
        }

        if self.platform == "Windows":
            results["local_services"] = self._get_local_services_windows()
        elif self.platform in ["Linux", "Darwin"]:
            results["local_services"] = self._get_local_services_linux()
        else:
            results["status"] = "skipped"

        if network_scan:
            open_ports = self._scan_network_ports(self.allowed_scan_ranges, self.max_ports_per_scan)
            scanned_services = [self._fingerprint_service(p["host"], p["port"]) for p in open_ports]
            results["network_services"] = scanned_services
            
            all_services = results["local_services"] + results["network_services"]
            results["privileged_services"] = self._identify_privileged_services(all_services)
            results["vulnerable_services"] = self._detect_vulnerable_services(all_services)
        
        results["execution_time"] = f"{time.perf_counter() - start_time:.4f} seconds"
        return results

if __name__ == '__main__':
    detector = T1046NetworkServiceDiscovery()
    # Example of a comprehensive scan
    scan_results = detector.run_checks(network_scan=True)
    print(json.dumps(scan_results, indent=2))
