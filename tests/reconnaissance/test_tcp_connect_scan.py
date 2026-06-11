# -*- coding: utf-8 -*-
"""
Tests for src.reconnaissance.tcp_connect_scan
Covers: validate_target, validate_and_parse_ports, validate_threads,
        port_scanner (mocked socket), and worker thread helper.
"""
import unittest
import socket
from queue import Queue
from unittest.mock import patch, MagicMock

from src.reconnaissance.tcp_connect_scan import (
    validate_target,
    validate_and_parse_ports,
    validate_threads,
    port_scanner,
    worker,
)


class TestValidateTarget(unittest.TestCase):
    """Unit tests for the validate_target helper."""

    def test_valid_ipv4(self):
        self.assertTrue(validate_target("192.168.1.1"))

    def test_valid_hostname(self):
        self.assertTrue(validate_target("example.com"))

    def test_valid_subdomain(self):
        self.assertTrue(validate_target("sub.example.co.uk"))

    def test_valid_localhost(self):
        self.assertTrue(validate_target("localhost"))

    def test_invalid_with_spaces(self):
        self.assertFalse(validate_target("192.168 .1.1"))

    def test_invalid_empty_string(self):
        self.assertFalse(validate_target(""))

    def test_invalid_special_characters(self):
        self.assertFalse(validate_target("exa!mple.com"))


class TestValidateAndParsePorts(unittest.TestCase):
    """Unit tests for the validate_and_parse_ports helper."""

    def test_single_port(self):
        result = validate_and_parse_ports("80")
        self.assertEqual(result, [80])

    def test_port_range(self):
        result = validate_and_parse_ports("1-5")
        self.assertEqual(result, [1, 2, 3, 4, 5])

    def test_comma_separated_ports(self):
        result = validate_and_parse_ports("22,80,443")
        self.assertEqual(result, [22, 80, 443])

    def test_mixed_format(self):
        result = validate_and_parse_ports("22,80-82,443")
        self.assertEqual(result, [22, 80, 81, 82, 443])

    def test_deduplication(self):
        result = validate_and_parse_ports("80,80,80")
        self.assertEqual(result, [80])

    def test_sorted_output(self):
        result = validate_and_parse_ports("443,22,80")
        self.assertEqual(result, [22, 80, 443])

    def test_invalid_port_zero(self):
        self.assertIsNone(validate_and_parse_ports("0"))

    def test_invalid_port_over_max(self):
        self.assertIsNone(validate_and_parse_ports("65536"))

    def test_invalid_reversed_range(self):
        self.assertIsNone(validate_and_parse_ports("100-50"))

    def test_invalid_non_numeric(self):
        self.assertIsNone(validate_and_parse_ports("abc"))

    def test_invalid_empty_string(self):
        self.assertIsNone(validate_and_parse_ports(""))

    def test_boundary_port_1(self):
        result = validate_and_parse_ports("1")
        self.assertEqual(result, [1])

    def test_boundary_port_65535(self):
        result = validate_and_parse_ports("65535")
        self.assertEqual(result, [65535])


class TestValidateThreads(unittest.TestCase):
    """Unit tests for the validate_threads helper in tcp_connect_scan."""

    def test_valid_minimum(self):
        self.assertTrue(validate_threads(1))

    def test_valid_maximum(self):
        self.assertTrue(validate_threads(100))

    def test_invalid_zero(self):
        self.assertFalse(validate_threads(0))

    def test_invalid_above_max(self):
        self.assertFalse(validate_threads(101))

    def test_invalid_negative(self):
        self.assertFalse(validate_threads(-1))


class TestPortScanner(unittest.TestCase):
    """Unit tests for the port_scanner function using a mocked socket."""

    @patch("src.reconnaissance.tcp_connect_scan.socket.socket")
    def test_open_port_detected(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0  # 0 means open
        mock_socket_class.return_value = mock_sock
        # Should not raise; open port logs an INFO message
        port_scanner(80, "127.0.0.1")
        mock_sock.connect_ex.assert_called_once_with(("127.0.0.1", 80))
        mock_sock.close.assert_called_once()

    @patch("src.reconnaissance.tcp_connect_scan.socket.socket")
    def test_closed_port_detected(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # Connection refused
        mock_socket_class.return_value = mock_sock
        port_scanner(9999, "127.0.0.1")
        mock_sock.connect_ex.assert_called_once_with(("127.0.0.1", 9999))
        mock_sock.close.assert_called_once()

    @patch("src.reconnaissance.tcp_connect_scan.socket.socket")
    def test_socket_error_handled_gracefully(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.error("Network unreachable")
        mock_socket_class.return_value = mock_sock
        # Should not raise; errors are caught and logged
        port_scanner(443, "10.0.0.1")
        mock_sock.close.assert_called_once()


class TestWorker(unittest.TestCase):
    """Unit tests for the worker thread function in tcp_connect_scan."""

    @patch("src.reconnaissance.tcp_connect_scan.port_scanner")
    def test_worker_processes_all_ports(self, mock_port_scanner):
        q = Queue()
        for port in [22, 80, 443]:
            q.put(port)
        worker(q, "127.0.0.1")
        self.assertTrue(q.empty())
        self.assertEqual(mock_port_scanner.call_count, 3)

    @patch("src.reconnaissance.tcp_connect_scan.port_scanner")
    def test_worker_empty_queue(self, mock_port_scanner):
        q = Queue()
        worker(q, "127.0.0.1")
        mock_port_scanner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
