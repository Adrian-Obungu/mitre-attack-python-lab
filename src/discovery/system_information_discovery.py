"""
This module implements the T1082SystemInformationDiscovery class, which is designed
to gather comprehensive, security-relevant system information. It covers system details,
hardware specs, network configuration, and security posture.

The class adheres to MITRE ATT&CK® technique T1082: System Information Discovery.
"""
import datetime
import logging
import platform
import re
import socket
import subprocess
from typing import Any, Dict, List, Optional
import os

import psutil

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class T1082SystemInformationDiscovery:
    """
    T1082: System Information Discovery.

    Collects comprehensive, security-relevant system information with a focus
    on safety, privacy, and cross-platform compatibility.
    """

    def __init__(self, mask_sensitive: bool = False, timeout: int = 2):
        """
        Initializes the discovery tool.

        Args:
            mask_sensitive (bool): If True, masks public IPs and hostnames.
            timeout (int): Timeout in seconds for network operations.
        """
        self.mask_sensitive = mask_sensitive
        self.timeout = timeout
        self.os_type = platform.system().lower()

    def run_checks(self) -> Dict[str, Any]:
        """
        Runs all information discovery checks and returns a structured dictionary.

        Returns:
            Dict[str, Any]: A dictionary containing system, hardware, network,
                            and security information.
        """
        system_info = self._get_system_info()
        hardware_info = self._get_hardware_info()
        network_info = self._get_network_info()
        security_info = self._get_security_info()

        return {
            "system": system_info,
            "hardware": hardware_info,
            "network": network_info,
            "security": security_info,
        }

    def _get_system_info(self) -> Dict[str, Any]:
        """Collects basic OS and system information using the `platform` module."""
        try:
            boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.datetime.now() - boot_time

            return {
                "os": {
                    "name": platform.system(),
                    "version": platform.version(),
                    "release": platform.release(),
                    "architecture": platform.machine(),
                },
                "hostname": "MASKED" if self.mask_sensitive else socket.gethostname(),
                "uptime": str(uptime),
            }
        except Exception as e:
            logging.error(f"Error collecting system info: {e}")
            return {}

    def _get_hardware_info(self) -> Dict[str, Any]:
        """Collects hardware information (CPU, memory, disk) via `psutil`."""
        try:
            # CPU Info
            cpu_info = {
                "cores": psutil.cpu_count(logical=False),
                "logical_processors": psutil.cpu_count(logical=True),
                "current_load_percent": psutil.cpu_percent(interval=1),
            }

            # Memory Info
            mem = psutil.virtual_memory()
            memory_info = {
                "total_gb": round(mem.total / (1024**3), 2),
                "available_gb": round(mem.available / (1024**3), 2),
                "used_percent": mem.percent,
            }

            # Disk Info
            disk_info = []
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disk_info.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "total_gb": round(usage.total / (1024**3), 2),
                        "used_percent": usage.percent,
                    })
                except (FileNotFoundError, PermissionError) as e:
                    logging.warning(f"Could not access disk partition {part.mountpoint}: {e}")

            return {"cpu": cpu_info, "memory": memory_info, "disks": disk_info}
        except Exception as e:
            logging.error(f"Error collecting hardware info: {e}")
            return {}

    def _is_public_ip(self, ip: str) -> bool:
        """Checks if an IP address is public."""
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            return False  # Not a valid IPv4 address
        
        private_ranges = [
            re.compile(r"^10\."),
            re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
            re.compile(r"^192\.168\."),
            re.compile(r"^127\."),
            re.compile(r"^169\.254\.")
        ]
        return not any(r.match(ip) for r in private_ranges)

    def _get_network_info(self) -> Dict[str, Any]:
        """Collects network interface and DNS information."""
        try:
            interfaces = []
            for name, addrs in psutil.net_if_addrs().items():
                interface_details: Dict[str, Any] = {"name": name, "ip": None, "mac": None}
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        if self.mask_sensitive and self._is_public_ip(ip):
                            interface_details["ip"] = "MASKED"
                        else:
                            interface_details["ip"] = ip
                    elif addr.family == psutil.AF_LINK:
                        interface_details["mac"] = addr.address
                interfaces.append(interface_details)
            
            # DNS servers
            dns_servers = []
            try:
                # This approach is more reliable across OSes than reading /etc/resolv.conf
                if self.os_type == 'windows':
                    result = subprocess.run(
                        ['powershell', 'Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses'],
                        capture_output=True, text=True, check=True, timeout=self.timeout
                    )
                    dns_servers = [s for s in result.stdout.strip().splitlines() if s]
                else: # Linux/macOS
                    with open('/etc/resolv.conf', 'r') as f:
                        for line in f:
                            if line.strip().startswith('nameserver'):
                                dns_servers.append(line.strip().split()[1])
            except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                logging.warning(f"Could not determine DNS servers: {e}")

            return {"interfaces": interfaces, "dns_servers": dns_servers}
        except Exception as e:
            logging.error(f"Error collecting network info: {e}")
            return {}

    def _get_security_info(self) -> Dict[str, Any]:
        """
        Collects security-related information (firewall, AV, updates).
        This method uses platform-specific commands and provides a baseline.
        """
        security_info: Dict[str, Any] = {
            "firewall_status": "unknown",
            "antivirus_status": "unknown",
            "uac_status": "not_applicable",
            "last_update_time": "unknown",
        }

        try:
            if self.os_type == "windows":
                # Firewall Status (Domain, Private, Public)
                fw_cmd = 'powershell -Command "Get-NetFirewallProfile | Select-Object Name, Enabled"'
                fw_output = subprocess.check_output(fw_cmd, shell=True, text=True, timeout=self.timeout)
                security_info["firewall_status"] = fw_output.strip()

                # Antivirus Status
                av_cmd = r'powershell -Command "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState | ConvertTo-Json"'
                av_output = subprocess.check_output(av_cmd, shell=True, text=True, timeout=self.timeout)
                security_info["antivirus_status"] = av_output.strip()

                # UAC Status
                uac_cmd = r'powershell -Command "(Get-ItemProperty -Path \'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\').EnableLUA"'
                uac_output = subprocess.check_output(uac_cmd, shell=True, text=True, timeout=self.timeout)
                security_info["uac_status"] = "enabled" if uac_output.strip() == "1" else "disabled"
                
                # Last Update Time
                update_cmd = r'powershell -Command "Get-WinEvent -ProviderName \'Microsoft-Windows-WindowsUpdateClient\' -MaxEvents 1 | Where-Object {$_.Id -eq 19} | Select-Object -ExpandProperty TimeCreated"'
                update_output = subprocess.check_output(update_cmd, shell=True, text=True, timeout=self.timeout)
                security_info["last_update_time"] = update_output.strip()

            elif self.os_type == "linux":
                # Firewall Status (UFW)
                try:
                    fw_output = subprocess.check_output("sudo ufw status", shell=True, text=True, stderr=subprocess.DEVNULL, timeout=self.timeout)
                    security_info["firewall_status"] = "active" if "Status: active" in fw_output else "inactive"
                except (subprocess.CalledProcessError, FileNotFoundError):
                    security_info["firewall_status"] = "ufw_not_found"

                # Antivirus (ClamAV)
                try:
                    av_output = subprocess.check_output("systemctl is-active clamav-daemon", shell=True, text=True, stderr=subprocess.DEVNULL, timeout=self.timeout)
                    security_info["antivirus_status"] = av_output.strip()
                except (subprocess.CalledProcessError, FileNotFoundError):
                    security_info["antivirus_status"] = "clamav_not_found_or_inactive"
                
                # Last update time from package manager logs
                if psutil.LINUX:
                    if os.path.exists("/var/log/dpkg.log"): # Debian/Ubuntu
                         last_update_cmd = "grep ' upgrade ' /var/log/dpkg.log | tail -n 1 | awk '{print $1, $2}'"
                    elif os.path.exists("/var/log/yum.log"): # CentOS/RHEL
                        last_update_cmd = "grep 'Updated:' /var/log/yum.log | tail -n 1 | awk '{print $1, $2, $3}'"
                    else:
                        last_update_cmd = ""
                    if last_update_cmd:
                         try:
                            update_output = subprocess.check_output(last_update_cmd, shell=True, text=True, timeout=self.timeout)
                            security_info["last_update_time"] = update_output.strip()
                         except subprocess.CalledProcessError:
                             pass # No updates found
            
            elif self.os_type == "darwin": # macOS
                # Firewall Status
                fw_cmd = "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
                fw_output = subprocess.check_output(fw_cmd, shell=True, text=True, timeout=self.timeout)
                security_info["firewall_status"] = "enabled" if "State = 1" in fw_output else "disabled"
                
                # Last update time
                update_cmd = "system_profiler SPInstallHistoryDataType | grep -A 5 'macOS' | grep 'Install Date' | tail -n 1"
                update_output = subprocess.check_output(update_cmd, shell=True, text=True, timeout=self.timeout)
                security_info["last_update_time"] = update_output.split(":", 1)[-1].strip()


        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.warning(f"A security check command failed or timed out on {self.os_type}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during security checks: {e}")

        return security_info