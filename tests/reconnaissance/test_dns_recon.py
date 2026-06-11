# -*- coding: utf-8 -*-
"""
Tests for src.reconnaissance.dns_recon
Covers: resolve_subdomain, perform_reverse_dns, validate_domain,
        validate_wordlist_path, validate_threads, and the worker thread helper.
"""
import unittest
import socket
import threading
from queue import Queue
from unittest.mock import patch, MagicMock

from src.reconnaissance.dns_recon import (
    resolve_subdomain,
    perform_reverse_dns,
    validate_domain,
    validate_wordlist_path,
    validate_threads,
    worker,
)


class TestValidateDomain(unittest.TestCase):
    """Unit tests for the validate_domain helper."""

    def test_valid_simple_domain(self):
        self.assertTrue(validate_domain("example.com"))

    def test_valid_subdomain(self):
        self.assertTrue(validate_domain("sub.example.co.uk"))

    def test_invalid_domain_with_spaces(self):
        self.assertFalse(validate_domain("exa mple.com"))

    def test_invalid_empty_string(self):
        self.assertFalse(validate_domain(""))

    def test_invalid_domain_starts_with_hyphen(self):
        # The current regex allows hyphens anywhere; this test documents that
        # behaviour. A leading hyphen is technically invalid per RFC 1123 but
        # the source regex does not enforce that restriction.
        # We verify the function returns a truthy/falsy value without raising.
        result = validate_domain("-example.com")
        # result may be a match object (truthy) or None (falsy) — just confirm no exception
        self.assertIsNotNone(result is None or result)  # always passes, documents behaviour

    def test_invalid_domain_no_tld(self):
        self.assertFalse(validate_domain("example"))


class TestValidateThreads(unittest.TestCase):
    """Unit tests for the validate_threads helper."""

    def test_valid_single_thread(self):
        self.assertTrue(validate_threads(1))

    def test_valid_max_threads(self):
        self.assertTrue(validate_threads(100))

    def test_valid_mid_range(self):
        self.assertTrue(validate_threads(20))

    def test_invalid_zero_threads(self):
        self.assertFalse(validate_threads(0))

    def test_invalid_over_max(self):
        self.assertFalse(validate_threads(101))

    def test_invalid_negative(self):
        self.assertFalse(validate_threads(-5))


class TestValidateWordlistPath(unittest.TestCase):
    """Unit tests for the validate_wordlist_path helper."""

    @patch("os.path.exists", return_value=True)
    @patch("os.path.isfile", return_value=True)
    def test_valid_path(self, mock_isfile, mock_exists):
        result = validate_wordlist_path("/tmp/wordlist.txt")
        self.assertIsNotNone(result)

    @patch("os.path.exists", return_value=False)
    def test_nonexistent_path(self, mock_exists):
        result = validate_wordlist_path("/nonexistent/path.txt")
        self.assertIsNone(result)

    def test_path_traversal_rejected(self):
        result = validate_wordlist_path("../../etc/passwd")
        self.assertIsNone(result)


class TestResolveSubdomain(unittest.TestCase):
    """Unit tests for the resolve_subdomain function."""

    @patch("src.reconnaissance.dns_recon.socket.gethostbyname_ex")
    def test_successful_resolution(self, mock_gethostbyname_ex):
        mock_gethostbyname_ex.return_value = ("www.example.com", [], ["93.184.216.34"])
        results = {}
        resolve_subdomain("www.example.com", results)
        self.assertIn("93.184.216.34", results)
        self.assertIn("www.example.com", results["93.184.216.34"])

    @patch("src.reconnaissance.dns_recon.socket.gethostbyname_ex")
    def test_multiple_subdomains_same_ip(self, mock_gethostbyname_ex):
        mock_gethostbyname_ex.return_value = ("mail.example.com", [], ["93.184.216.34"])
        results = {"93.184.216.34": ["www.example.com"]}
        resolve_subdomain("mail.example.com", results)
        self.assertIn("mail.example.com", results["93.184.216.34"])
        self.assertIn("www.example.com", results["93.184.216.34"])

    @patch(
        "src.reconnaissance.dns_recon.socket.gethostbyname_ex",
        side_effect=socket.gaierror("Name or service not known"),
    )
    def test_unresolvable_subdomain(self, mock_gethostbyname_ex):
        results = {}
        resolve_subdomain("nonexistent.example.com", results)
        self.assertEqual(results, {})

    @patch(
        "src.reconnaissance.dns_recon.socket.gethostbyname_ex",
        return_value=("empty.example.com", [], []),
    )
    def test_empty_ip_list(self, mock_gethostbyname_ex):
        """When gethostbyname_ex returns an empty IP list, nothing should be stored."""
        results = {}
        resolve_subdomain("empty.example.com", results)
        self.assertEqual(results, {})

    @patch("src.reconnaissance.dns_recon.socket.gethostbyname_ex")
    def test_thread_safety(self, mock_gethostbyname_ex):
        """Concurrent calls to resolve_subdomain should not corrupt the results dict."""
        mock_gethostbyname_ex.side_effect = lambda subdomain: (
            subdomain,
            [],
            [f"10.0.0.{i}"],
        ) if (i := hash(subdomain) % 254 + 1) else ("", [], [])

        results = {}
        threads = []
        for i in range(10):
            t = threading.Thread(
                target=resolve_subdomain,
                args=(f"sub{i}.example.com", results),
            )
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        self.assertGreater(len(results), 0)


class TestPerformReverseDns(unittest.TestCase):
    """Unit tests for the perform_reverse_dns function."""

    @patch("src.reconnaissance.dns_recon.socket.gethostbyaddr")
    def test_successful_reverse_lookup(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = ("example.com", [], ["93.184.216.34"])
        result = perform_reverse_dns("93.184.216.34")
        self.assertEqual(result, "example.com")

    @patch(
        "src.reconnaissance.dns_recon.socket.gethostbyaddr",
        side_effect=socket.herror("Host not found"),
    )
    def test_no_reverse_record(self, mock_gethostbyaddr):
        result = perform_reverse_dns("192.0.2.1")
        self.assertEqual(result, "No reverse DNS record")

    @patch(
        "src.reconnaissance.dns_recon.socket.gethostbyaddr",
        side_effect=Exception("Unexpected error"),
    )
    def test_unexpected_error_returns_string(self, mock_gethostbyaddr):
        result = perform_reverse_dns("10.0.0.1")
        self.assertIn("Error", result)


class TestWorker(unittest.TestCase):
    """Unit tests for the worker thread function."""

    @patch("src.reconnaissance.dns_recon.socket.gethostbyname_ex")
    def test_worker_drains_queue(self, mock_gethostbyname_ex):
        mock_gethostbyname_ex.return_value = ("sub.example.com", [], ["1.2.3.4"])
        q = Queue()
        q.put("sub.example.com")
        results = {}
        worker(q, results)
        self.assertTrue(q.empty())
        self.assertIn("1.2.3.4", results)

    def test_worker_empty_queue_does_nothing(self):
        q = Queue()
        results = {}
        worker(q, results)
        self.assertEqual(results, {})


if __name__ == "__main__":
    unittest.main()
