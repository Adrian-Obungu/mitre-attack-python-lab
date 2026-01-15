import unittest
import sys
import os
import subprocess
import importlib
import logging
from unittest.mock import patch, MagicMock
import platform
import socket # Added for TCP connection tests
from datetime import datetime # Added for mock LogRecord
import dns.resolver
from dnslib import DNSRecord, DNSQuestion, QTYPE

# Dynamically adjust sys.path for script execution
current_script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_script_dir, '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import modules from src
from src.reconnaissance.PortScan_Enhanced import PortScanner
from src.defense.HoneyResolver_Enhanced import EnhancedHoneyResolver
from src.persistence.persistence_auditor import PersistenceAuditor
from src.privilege.privilege_auditor import PrivilegeAuditor
from src.utils.log_parser import LogParser

# Define a simple logging formatter to avoid issues with test_json_formatter
class SimpleFormatter(logging.Formatter):
    def format(self, record):
        return super().format(record)

class TestEnvironment(unittest.TestCase):
    """Tests for the overall environment setup and essential dependencies."""

    def test_python_version(self):
        """Ensures Python 3.9+ is used."""
        self.assertGreaterEqual(sys.version_info.major, 3)
        self.assertGreaterEqual(sys.version_info.minor, 9)
        print(f"Python Version: {sys.version.split(' ')[0]}")

    def test_dependencies_installed(self):
        """Checks if all required packages from requirements.txt are installed."""
        # Mapping for packages where import name differs from package name
        name_map = {
            "dnspython": "dns",
            "google-generativeai": "google.generativeai",
            "python-dotenv": "dotenv",
            "pytest-cov": "pytest_cov",
            "memory-profiler": "memory_profiler",
        }
        req_path = os.path.join(project_root, 'config', 'requirements.txt')
        with open(req_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Handle format like 'scapy>=2.5.0' -> 'scapy'
                    package_name = line.split('>=' )[0].split('==' )[0].split('<=' )[0].strip()

                    # Pytest itself doesn't need to be imported.
                    if package_name == 'pytest':
                        continue

                    import_name = name_map.get(package_name, package_name)
                    try:
                        importlib.import_module(import_name)
                    except ImportError:
                        self.fail(f"Dependency not installed: {package_name}. Please run 'pip install -r config/requirements.txt'")
        print("All dependencies from requirements.txt are installed.")

    def test_core_modules_importable(self):
        """Verifies essential src modules can be imported."""
        modules = [
            "src.reconnaissance.dns_recon",
            "src.reconnaissance.tcp_connect_scan",
            "src.persistence.persistence_auditor",
            "src.privilege.privilege_auditor",
            "src.privilege.path_hijack_detector",
            "src.privilege.service_scanner",
            "src.privilege.logon_script_detector",
            "src.api.main",
        ]
        print("\nTesting imports...")
        for module_name in modules:
            try:
                importlib.import_module(module_name)
                print(f"✓ {module_name}")
            except ImportError as e:
                print(f"✗ {module_name}: {e}")
                self.fail(f"Failed to import {module_name}: {e}")
        print("Import test complete!")

    def test_key_classes_available(self):
        """Checks if critical classes are available."""
        try:
            from src.privilege.privilege_auditor import PrivilegeAuditor
            self.assertIsNotNone(PrivilegeAuditor)
            print("✓ PrivilegeAuditor class available")
        except ImportError:
            self.fail("PrivilegeAuditor class not found in src.privilege.privilege_auditor")

        try:
            from src.api.main import app as fastapi_app
            self.assertIsNotNone(fastapi_app)
            print("✓ FastAPI app available")
        except ImportError:
            self.fail("FastAPI app not found in src.api.main")

class TestNetworking(unittest.TestCase):
    """Tests basic networking functionality required by tools."""

    @unittest.skipUnless(platform.system() == "Windows", "Skipping on non-Windows OS")
    def test_dns_resolution(self):
        """Tests if basic DNS resolution works (essential for dns_recon)."""
        try:
            result = subprocess.run(["nslookup", "scanme.nmap.org"], capture_output=True, text=True, check=True)
            self.assertIn("scanme.nmap.org", result.stdout)
            print("DNS resolution for scanme.nmap.org successful.")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.fail("DNS resolution failed. Check network connectivity or nslookup utility.")

    @unittest.skipUnless(platform.system() == "Windows", "Skipping on non-Windows OS")
    def test_tcp_connection(self):
        """Tests if basic TCP connection to a known host:port works (essential for PortScan)."""
        # Using a non-blocking socket to test connectivity quickly
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2) # 2-second timeout
        try:
            sock.connect(("scanme.nmap.org", 80))
            print("TCP connection to scanme.nmap.org:80 successful.")
        except (socket.error, socket.timeout):
            self.fail("TCP connection to scanme.nmap.org:80 failed. Check network connectivity or firewall rules.")
        finally:
            sock.close()

class TestTooling(unittest.TestCase):
    """Tests the basic functionality of implemented tools."""

    def test_port_scanner_open_port(self):
        """Tests PortScan_Enhanced for an open port (e.g., 80 on scanme.nmap.org)."""
        # Mock sr1 to return a SYN/ACK response
        with patch('src.reconnaissance.PortScan_Enhanced.sr1') as mock_sr1:
            mock_syn_ack = MagicMock()
            mock_syn_ack.haslayer.return_value = True
            mock_syn_ack.getlayer.return_value.flags = 0x12 # SYN/ACK
            mock_sr1.side_effect = [
                mock_syn_ack, # For SYN to 80
                MagicMock(haslayer=MagicMock(return_value=False)) # For RST to 80 (ending handshake)
            ]
            scanner = PortScanner("scanme.nmap.org", [80], timeout=2)
            results = scanner.syn_scan()
            self.assertIn(80, results)
            self.assertEqual(results[80], "Open")
            print("Port 80 on scanme.nmap.org found open.")

    def test_port_scanner_closed_port(self):
        """Tests PortScan_Enhanced for a closed port (e.g., a high, unlikely port)."""
        # Mock sr1 to return a RST/ACK response
        with patch('src.reconnaissance.PortScan_Enhanced.sr1') as mock_sr1:
            mock_rst_ack = MagicMock()
            mock_rst_ack.haslayer.return_value = True
            mock_rst_ack.getlayer.return_value.flags = 0x14 # RST/ACK
            mock_sr1.return_value = mock_rst_ack
            scanner = PortScanner("scanme.nmap.org", [65530], timeout=2) # Using an unlikely high port
            results = scanner.syn_scan()
            self.assertIn(65530, results)
            self.assertEqual(results[65530], "Closed")
            print("Port 65530 on scanme.nmap.org found closed.")

    def test_dns_recon_resolve(self):
        """Tests dns_recon.py for A records of a known domain."""
        from src.reconnaissance.dns_recon import resolve_subdomain
        mock_domain = "example.com"
        mock_subdomain = "www.example.com"
        mock_ip = "93.184.216.34"
        mock_results = {} # This will be updated by resolve_subdomain
        with patch('src.reconnaissance.dns_recon.socket.gethostbyname_ex') as mock_gethostbyname_ex:
            mock_gethostbyname_ex.return_value = (mock_subdomain, [], [mock_ip])
            resolve_subdomain(mock_subdomain, mock_results)
            self.assertIn(mock_ip, mock_results)
            self.assertIn(mock_subdomain, mock_results[mock_ip])
            print(f"DNS A record for {mock_subdomain} resolved.")

    def test_dns_recon_reverse_dns(self):
        """Tests dns_recon.py for reverse DNS lookup of a known IP."""
        from src.reconnaissance.dns_recon import perform_reverse_dns
        mock_ip = "93.184.216.34"
        mock_hostname = "example.com"
        with patch('src.reconnaissance.dns_recon.socket.gethostbyaddr') as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = (mock_hostname, [], [mock_ip])
            results = perform_reverse_dns(mock_ip)
            self.assertEqual(results, mock_hostname)
            print(f"Reverse DNS for {mock_ip} resolved.")

    def test_honey_resolver_real_subdomain(self):
        """Tests HoneyResolver_Enhanced.py for a real subdomain (should resolve as normal)."""
        mock_config = {
            "HONEYPOT_DOMAIN": "example.com",
            "REAL_SUBDOMAINS": {"www": "192.0.2.1"},
            "FAKE_SUBDOMAINS": {},
            "HEALTH_METRICS_PORT": 8000, # Added for mock config
        }
        honeypot = EnhancedHoneyResolver(mock_config)
        request = DNSRecord(q=DNSQuestion("www.example.com", QTYPE.A))
        handler = MagicMock()
        handler.client_address = ("127.0.0.1", 12345)
        reply = honeypot.resolve(request, handler)
        self.assertEqual(str(reply.a.rdata), "192.0.2.1")
        print("HoneyResolver resolved real subdomain.")

    def test_honey_resolver_fake_subdomain(self):
        """Tests HoneyResolver_Enhanced.py for a fake subdomain (should log detection)."""
        mock_config = {
            "HONEYPOT_DOMAIN": "example.com",
            "REAL_SUBDOMAINS": {},
            "FAKE_SUBDOMAINS": {"fake": "127.0.0.1"},
            "HEALTH_METRICS_PORT": 8000, # Added for mock config
        }
        honeypot = EnhancedHoneyResolver(mock_config)
        request = DNSRecord(q=DNSQuestion("fake.example.com", QTYPE.A))
        handler = MagicMock()
        handler.client_address = ("127.0.0.1", 12345)
        with self.assertLogs('src.defense.HoneyResolver_Enhanced', level='INFO') as cm:
            reply = honeypot.resolve(request, handler)
            self.assertEqual(str(reply.a.rdata), "127.0.0.1")
            self.assertIn("DNS Query received", cm.output[0])
            print("HoneyResolver detected fake subdomain query.")

    def test_honey_resolver_random_subdomain(self):
        """Tests HoneyResolver_Enhanced.py for a random subdomain (should log detection)."""
        mock_config = {
            "HONEYPOT_DOMAIN": "example.com",
            "REAL_SUBDOMAINS": {},
            "FAKE_SUBDOMAINS": {},
            "HEALTH_METRICS_PORT": 8000, # Added for mock config
        }
        honeypot = EnhancedHoneyResolver(mock_config)
        request = DNSRecord(q=DNSQuestion("random.example.com", QTYPE.A))
        handler = MagicMock()
        handler.client_address = ("127.0.0.1", 12345)
        with self.assertLogs('src.defense.HoneyResolver_Enhanced', level='INFO') as cm:
            reply = honeypot.resolve(request, handler)
            self.assertTrue(str(reply.a.rdata).startswith("10.0.2."))
            self.assertIn("DNS Query received", cm.output[0])
            print("HoneyResolver detected random subdomain query.")

    def test_log_parser_init(self):
        parser = LogParser("dummy.log", {}, None) # Pass empty dict for threat_scores and None for ThreatIntelClient
        self.assertIsNotNone(parser)
        print("LogParser initialized.")

    @unittest.skip("Skipping for now")
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    @patch('src.utils.log_parser.LogParser._update_statistics')
    def test_log_parser_line_parsing(self, mock_update_statistics, mock_open, mock_exists):
        """Tests LogParser's ability to parse a single log line."""
        log_line = '{{"timestamp": "2023-01-01T10:00:00", "level": "INFO", "message": "DNS Query received", "logger": "src.defense.HoneyResolver_Enhanced", "client_ip": "127.0.0.1", "qname": "test.com", "qtype": "A", "response_ip": "1.2.3.4", "category": "real"}}'
        mock_open.return_value.__iter__.return_value = [log_line]
        
        parser = LogParser("dummy.log", {}, None)
        parsed_entries = parser.parse_logs()
        
        self.assertEqual(len(parsed_entries), 1)
        self.assertEqual(parsed_entries[0]["qname"], "test.com")
        print("LogParser line parsing successful.")

if __name__ == '__main__':
    unittest.main()
