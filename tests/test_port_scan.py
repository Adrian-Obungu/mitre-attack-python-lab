import unittest
import sys
import os
import subprocess
import time
from unittest.mock import patch, MagicMock
import dns.resolver
import dns.exception # Import dns.exception

# Dynamically adjust sys.path for script execution
current_script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_script_dir, '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import module to be tested
from src.reconnaissance.PortScan_Enhanced import PortScanner

class TestPortScanEnhanced(unittest.TestCase):

    def test_syn_scan_mock(self):
        """Test SYN scan with a mock for sr1 to control responses."""
        mock_target = "127.0.0.1"
        mock_ports = [80, 443]

        with patch('src.reconnaissance.PortScan_Enhanced.sr1') as mock_sr1:
            # Mock response for port 80 (SYN/ACK -> Open)
            mock_syn_ack = MagicMock()
            mock_syn_ack.haslayer.return_value = True
            mock_syn_ack.getlayer.return_value.flags = 0x12 # SYN/ACK

            # Mock response for port 443 (RST/ACK -> Closed)
            mock_rst_ack = MagicMock()
            mock_rst_ack.haslayer.return_value = True
            mock_rst_ack.getlayer.return_value.flags = 0x14 # RST/ACK

            # Configure side_effect to return different mocks for different calls
            # For port 80, first SYN/ACK, then RST (for the reset)
            # For port 443, just RST/ACK
            mock_sr1.side_effect = [
                mock_syn_ack, # For SYN to 80
                MagicMock(haslayer=MagicMock(return_value=False)), # For RST to 80 (should be sent but not necessarily receive a response in this simple mock)
                mock_rst_ack # For SYN to 443
            ]

            scanner = PortScanner(mock_target, mock_ports, timeout=1)
            results = scanner.syn_scan()

            self.assertIn(80, results)
            self.assertEqual(results[80], "Open")
            self.assertIn(443, results)
            self.assertEqual(results[443], "Closed")
            self.assertEqual(mock_sr1.call_count, 3) # Two SYNs, one RST

    def test_ack_scan_mock(self):
        """Test ACK scan with a mock for sr1."""
        mock_target = "127.0.0.1"
        mock_ports = [80]

        with patch('src.reconnaissance.PortScan_Enhanced.sr1') as mock_sr1:
            # Mock response for port 80 (RST -> Unfiltered)
            mock_rst = MagicMock()
            mock_rst.haslayer.return_value = True
            mock_rst.getlayer.return_value.flags = 0x4 # RST

            mock_sr1.return_value = mock_rst

            scanner = PortScanner(mock_target, mock_ports, timeout=1)
            results = scanner.ack_scan()

            self.assertIn(80, results)
            self.assertEqual(results[80], "Unfiltered (No Firewall or Stateless)")
            self.assertEqual(mock_sr1.call_count, 1)

    def test_xmas_scan_mock(self):
        """Test XMAS scan with a mock for sr1."""
        mock_target = "127.0.0.1"
        mock_ports = [22]

        with patch('src.reconnaissance.PortScan_Enhanced.sr1') as mock_sr1:
            # Mock response for port 22 (None -> Open|Filtered)
            mock_sr1.return_value = None

            scanner = PortScanner(mock_target, mock_ports, timeout=1)
            results = scanner.xmas_scan()

            self.assertIn(22, results)
            self.assertEqual(results[22], "Open|Filtered")
            self.assertEqual(mock_sr1.call_count, 1)

    def test_dns_scan_mock(self):
        """Test DNS scan with mock for dns.resolver.resolve."""
        mock_domain = "example.com"
        mock_a_record = MagicMock()
        mock_a_record.__str__.return_value = "192.0.2.1"
        mock_mx_record = MagicMock()
        mock_mx_record.__str__.return_value = "mail.example.com"
        mock_ns_record = MagicMock()
        mock_ns_record.__str__.return_value = "ns1.example.com"
        mock_txt_record = MagicMock()
        mock_txt_record.__str__.return_value = "v=spf1 include:_spf.example.com ~all"

        with patch('src.reconnaissance.PortScan_Enhanced.resolver.resolve') as mock_resolve:
            mock_resolve.side_effect = [
                [mock_a_record],  # For A record
                [mock_a_record],  # For AAAA record (re-use A mock for simplicity if no AAAA)
                [mock_mx_record], # For MX record
                [mock_ns_record], # For NS record
                [mock_txt_record],# For TXT record
                dns.resolver.NoAnswer # For SOA record
            ]

            results = PortScanner.dns_scan(mock_domain)

            self.assertIn("A", results)
            self.assertIn("192.0.2.1", results["A"])
            self.assertIn("MX", results)
            self.assertIn("mail.example.com", results["MX"])
            self.assertIn("NS", results)
            self.assertIn("ns1.example.com", results["NS"])
            self.assertIn("TXT", results)
            self.assertIn("v=spf1 include:_spf.example.com ~all", results["TXT"])
            self.assertIn("SOA", results)
            self.assertIn("No records found.", results["SOA"])

if __name__ == '__main__':
    unittest.main()
