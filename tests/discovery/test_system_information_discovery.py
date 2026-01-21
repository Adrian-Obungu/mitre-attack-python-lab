"""
This module contains tests for the T1082SystemInformationDiscovery class,
ensuring it correctly gathers system, hardware, network, and security information
across different platforms. It uses extensive mocking to simulate various OS
environments and command outputs.
"""

import platform
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, mock_open, patch
import socket
import os

# Dynamically determine the project's root path and add it to sys.path
# This allows imports to work regardless of where the script is run
import sys
# This path adjustment is crucial for the test runner to find the 'src' module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.discovery.system_information_discovery import T1082SystemInformationDiscovery

# Mock data for psutil
MOCK_BOOT_TIME = (datetime.now() - timedelta(days=1)).timestamp()

class MockPsutil:
    class AF_LINK:
        pass
    
    LINUX = False
    WINDOWS = False
    DARWIN = False
        
    def boot_time(self):
        return MOCK_BOOT_TIME

    def cpu_count(self, logical=True):
        return 8 if logical else 4

    def cpu_percent(self, interval=None):
        return 15.5

    def virtual_memory(self):
        mock_mem = MagicMock()
        mock_mem.total = 16 * 1024**3  # 16 GB
        mock_mem.available = 8 * 1024**3 # 8 GB
        mock_mem.percent = 50.0
        return mock_mem

    def disk_partitions(self):
        mock_part = MagicMock()
        mock_part.device = "/dev/sda1"
        mock_part.mountpoint = "/"
        mock_part.fstype = "ext4"
        return [mock_part]

    def disk_usage(self, path):
        mock_usage = MagicMock()
        mock_usage.total = 500 * 1024**3 # 500 GB
        mock_usage.used = 100 * 1024**3  # 100 GB
        mock_usage.percent = 20.0
        return mock_usage

    def net_if_addrs(self):
        mock_addr_inet = MagicMock()
        mock_addr_inet.family = socket.AF_INET
        mock_addr_inet.address = "8.8.8.8" # Public IP for masking test

        mock_addr_link = MagicMock()
        mock_addr_link.family = self.AF_LINK
        mock_addr_link.address = "00:1A:2B:3C:4D:5E"
        
        mock_addr_private = MagicMock()
        mock_addr_private.family = socket.AF_INET
        mock_addr_private.address = "192.168.1.100"
        
        return {
            "eth0": [mock_addr_inet, mock_addr_link],
            "lo": [MagicMock(family=socket.AF_INET, address="127.0.0.1")],
            "wifi0": [mock_addr_private, MagicMock(family=self.AF_LINK, address="AA:BB:CC:DD:EE:FF")]
        }

# Mock socket separately as it's a standard library
class MockSocketModule:
    AF_INET = 2
    def gethostname(self):
        return "mock-hostname"

# Patching at the class level to avoid repetition in every test
@patch('src.discovery.system_information_discovery.psutil', MockPsutil())
@patch('src.discovery.system_information_discovery.socket', MockSocketModule())
class TestSystemInformationDiscovery(unittest.TestCase):
    """Test suite for T1082SystemInformationDiscovery."""

    def test_init(self):
        """Test constructor sets properties correctly."""
        detector = T1082SystemInformationDiscovery(mask_sensitive=True, timeout=5)
        self.assertTrue(detector.mask_sensitive)
        self.assertEqual(detector.timeout, 5)

    @patch('src.discovery.system_information_discovery.platform')
    def test_get_system_info(self, mock_platform):
        """Test collection of basic system information."""
        mock_platform.system.return_value = "Linux"
        mock_platform.version.return_value = "#1 SMP Debian 5.10.70-1 (2021-09-28)"
        mock_platform.release.return_value = "5.10.0-8-amd64"
        mock_platform.machine.return_value = "x86_64"

        detector = T1082SystemInformationDiscovery()
        result = detector._get_system_info()

        self.assertEqual(result["os"]["name"], "Linux")
        self.assertEqual(result["os"]["architecture"], "x86_64")
        self.assertEqual(result["hostname"], "mock-hostname")
        self.assertTrue("1 day" in result["uptime"])
        
    def test_get_hardware_info(self):
        """Test collection of hardware specs."""
        detector = T1082SystemInformationDiscovery()
        result = detector._get_hardware_info()

        self.assertEqual(result["cpu"]["cores"], 4)
        self.assertEqual(result["cpu"]["logical_processors"], 8)
        self.assertEqual(result["memory"]["total_gb"], 16.0)
        self.assertEqual(result["disks"][0]["used_percent"], 20.0)

    def test_ip_masking(self):
        """Test that public IPs are masked when specified."""
        detector = T1082SystemInformationDiscovery(mask_sensitive=True)
        result = detector._get_network_info()

        interfaces = result["interfaces"]
        eth0 = next((iface for iface in interfaces if iface["name"] == "eth0"), None)
        wifi0 = next((iface for iface in interfaces if iface["name"] == "wifi0"), None)

        self.assertIsNotNone(eth0)
        self.assertEqual(eth0["ip"], "MASKED") # Public IP should be masked
        
        self.assertIsNotNone(wifi0)
        self.assertEqual(wifi0["ip"], "192.168.1.100") # Private IP should be preserved

    @patch('builtins.open', new_callable=mock_open, read_data="nameserver 8.8.8.8\nnameserver 8.8.4.4")
    def test_get_network_info_linux(self, mock_file):
        """Test network info collection on Linux."""
        with patch('src.discovery.system_information_discovery.platform.system', return_value="Linux"):
            detector = T1082SystemInformationDiscovery()
            result = detector._get_network_info()
            self.assertEqual(result["dns_servers"], ["8.8.8.8", "8.8.4.4"])
            self.assertEqual(len(result["interfaces"]), 3)

    @patch('src.discovery.system_information_discovery.subprocess.check_output')
    def test_security_info_windows(self, mock_subprocess):
        """Test security info collection on Windows."""
        # Simulate outputs from PowerShell commands
        mock_subprocess.side_effect = [
            "Domain, True\nPrivate, True\nPublic, False", # Firewall
            '[{"displayName": "Windows Defender", "productState": "397568"}]', # AV
            "1", # UAC
            "2023-10-26 10:00:00" # Last Update
        ]
        
        with patch('src.discovery.system_information_discovery.platform.system', return_value="Windows"):
            detector = T1082SystemInformationDiscovery()
            result = detector._get_security_info()

            self.assertIn("Domain, True", result["firewall_status"])
            self.assertIn("Windows Defender", result["antivirus_status"])
            self.assertEqual(result["uac_status"], "enabled")
            self.assertIn("2023", result["last_update_time"])

    def test_security_info_linux(self):
        """Test security info collection on Linux."""
        with patch('src.discovery.system_information_discovery.subprocess.check_output') as mock_subprocess, \
             patch('src.discovery.system_information_discovery.psutil.LINUX', True), \
             patch('os.path.exists', return_value=True):
            
            mock_subprocess.side_effect = [
                "Status: active", # ufw
                "active", # clamav
                "2023-10-27 11:00:00" # dpkg log
            ]

            with patch('src.discovery.system_information_discovery.platform.system', return_value="Linux"):
                detector = T1082SystemInformationDiscovery()
                result = detector._get_security_info()
            
            self.assertEqual(result["firewall_status"], "active")
            self.assertEqual(result["antivirus_status"], "active")
            self.assertIn("2023-10-27", result["last_update_time"])


    def test_run_all_checks(self):
        """Test the main run_checks orchestrator method."""
        detector = T1082SystemInformationDiscovery()
        # Mock the internal methods to test orchestration
        detector._get_system_info = MagicMock(return_value={"os": {"name": "TestOS"}})
        detector._get_hardware_info = MagicMock(return_value={"cpu": {"cores": 2}})
        detector._get_network_info = MagicMock(return_value={"interfaces": []})
        detector._get_security_info = MagicMock(return_value={"firewall": "on"})
        
        result = detector.run_checks()

        self.assertIn("system", result)
        self.assertIn("hardware", result)
        self.assertIn("network", result)
        self.assertIn("security", result)
        self.assertEqual(result["system"]["os"]["name"], "TestOS")
        self.assertEqual(result["hardware"]["cpu"]["cores"], 2)


if __name__ == '__main__':
    # This allows running the tests directly from the command line
    unittest.main(argv=['first-arg-is-ignored'], exit=False)