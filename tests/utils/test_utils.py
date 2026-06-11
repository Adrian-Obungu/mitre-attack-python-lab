# -*- coding: utf-8 -*-
"""
Tests for src.utils
Covers: JsonFormatter (logging_config), setup_logging, LogParser,
        validate_log_file_path, and ThreatIntelClient.
"""
import json
import logging
import os
import sys
import unittest
from io import StringIO
from unittest.mock import patch, MagicMock, mock_open

from src.utils.logging_config import JsonFormatter, setup_logging
from src.utils.log_parser import LogParser, validate_log_file_path
from src.utils.threat_intel import ThreatIntelClient


# ===========================================================================
# JsonFormatter (logging_config)
# ===========================================================================
class TestJsonFormatter(unittest.TestCase):
    """Tests for the JsonFormatter class in logging_config."""

    def _make_record(self, message="test message", level=logging.INFO):
        record = logging.LogRecord(
            name="test_logger",
            level=level,
            pathname="test.py",
            lineno=1,
            msg=message,
            args=(),
            exc_info=None,
        )
        return record

    def test_output_is_valid_json(self):
        formatter = JsonFormatter()
        record = self._make_record()
        output = formatter.format(record)
        parsed = json.loads(output)
        self.assertIsInstance(parsed, dict)

    def test_required_fields_present(self):
        formatter = JsonFormatter()
        record = self._make_record("hello world")
        parsed = json.loads(formatter.format(record))
        for field in ("timestamp", "level", "name", "message", "file", "line"):
            self.assertIn(field, parsed)

    def test_message_content_preserved(self):
        formatter = JsonFormatter()
        record = self._make_record("specific message")
        parsed = json.loads(formatter.format(record))
        self.assertEqual(parsed["message"], "specific message")

    def test_exception_info_included(self):
        formatter = JsonFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            record = logging.LogRecord(
                name="test", level=logging.ERROR, pathname="t.py",
                lineno=1, msg="error occurred", args=(), exc_info=sys.exc_info()
            )
        parsed = json.loads(formatter.format(record))
        self.assertIn("exc_info", parsed)

    def test_level_name_correct(self):
        formatter = JsonFormatter()
        record = self._make_record(level=logging.WARNING)
        parsed = json.loads(formatter.format(record))
        self.assertEqual(parsed["level"], "WARNING")


class TestSetupLogging(unittest.TestCase):
    """Tests for the setup_logging function."""

    def test_setup_logging_plain_format(self):
        setup_logging(level=logging.DEBUG, json_format=False)
        root_logger = logging.getLogger()
        self.assertGreater(len(root_logger.handlers), 0)

    def test_setup_logging_json_format(self):
        setup_logging(level=logging.INFO, json_format=True)
        root_logger = logging.getLogger()
        handlers = root_logger.handlers
        self.assertGreater(len(handlers), 0)
        # At least one handler should use JsonFormatter
        formatters = [h.formatter for h in handlers]
        self.assertTrue(any(isinstance(f, JsonFormatter) for f in formatters))

    def test_setup_logging_clears_existing_handlers(self):
        # Add a dummy handler first
        dummy = logging.StreamHandler()
        logging.root.addHandler(dummy)
        setup_logging(level=logging.INFO)
        # After setup, handlers should be freshly set (not duplicated)
        self.assertLessEqual(len(logging.root.handlers), 2)


# ===========================================================================
# LogParser
# ===========================================================================
class TestLogParserInit(unittest.TestCase):
    """Tests for LogParser initialisation."""

    def test_initialisation_with_empty_scores(self):
        parser = LogParser("dummy.log", {})
        self.assertEqual(parser.log_file_path, "dummy.log")
        self.assertEqual(parser.threat_scores, {})
        self.assertIsNone(parser.threat_intel_client)
        self.assertEqual(parser.total_queries, 0)

    def test_initialisation_with_threat_intel_client(self):
        mock_client = MagicMock()
        parser = LogParser("dummy.log", {}, threat_intel_client=mock_client)
        self.assertIs(parser.threat_intel_client, mock_client)


class TestLogParserParseLogLine(unittest.TestCase):
    """Tests for the _parse_log_line method."""

    def setUp(self):
        self.parser = LogParser("dummy.log", {})

    def _valid_entry(self, qname="test.example.com", category="real"):
        return json.dumps({
            "client_ip": "10.0.0.1",
            "qname": qname,
            "qtype": "A",
            "category": category,
        })

    def test_valid_json_line_parsed(self):
        self.parser._parse_log_line(self._valid_entry())
        self.assertEqual(len(self.parser.parsed_entries), 1)
        self.assertEqual(self.parser.parsed_entries[0]["client_ip"], "10.0.0.1")

    def test_honeypot_hit_flagged_for_fake_category(self):
        self.parser._parse_log_line(self._valid_entry(category="fake"))
        self.assertTrue(self.parser.parsed_entries[0]["is_honeypot_hit"])

    def test_honeypot_hit_flagged_for_random_category(self):
        self.parser._parse_log_line(self._valid_entry(category="random"))
        self.assertTrue(self.parser.parsed_entries[0]["is_honeypot_hit"])

    def test_real_category_not_flagged_as_honeypot_hit(self):
        self.parser._parse_log_line(self._valid_entry(category="real"))
        self.assertFalse(self.parser.parsed_entries[0]["is_honeypot_hit"])

    def test_invalid_json_line_ignored(self):
        self.parser._parse_log_line("this is not json\n")
        self.assertEqual(len(self.parser.parsed_entries), 0)

    def test_json_without_qname_ignored(self):
        self.parser._parse_log_line(json.dumps({"message": "startup"}))
        self.assertEqual(len(self.parser.parsed_entries), 0)


class TestLogParserUpdateStatistics(unittest.TestCase):
    """Tests for the _update_statistics method."""

    def setUp(self):
        self.parser = LogParser("dummy.log", {"fake_subdomain_query": 10})

    def test_total_queries_incremented(self):
        entry = {"client_ip": "1.2.3.4", "qname": "test.com", "qtype": "A", "is_honeypot_hit": False}
        self.parser._update_statistics(entry)
        self.assertEqual(self.parser.total_queries, 1)

    def test_honeypot_hit_increments_score(self):
        entry = {"client_ip": "1.2.3.4", "qname": "fake.example.com", "qtype": "A", "is_honeypot_hit": True}
        self.parser._update_statistics(entry)
        score = self.parser.query_stats["1.2.3.4"]["threat_score"]
        self.assertGreater(score, 0)

    def test_any_qtype_increments_score(self):
        self.parser.threat_scores["suspicious_qtype_query"] = 5
        entry = {"client_ip": "5.5.5.5", "qname": "test.com", "qtype": "ANY", "is_honeypot_hit": False}
        self.parser._update_statistics(entry)
        score = self.parser.query_stats["5.5.5.5"]["threat_score"]
        self.assertEqual(score, 5)

    def test_top_queried_domains_updated(self):
        entry = {"client_ip": "1.2.3.4", "qname": "popular.com", "qtype": "A", "is_honeypot_hit": False}
        self.parser._update_statistics(entry)
        self.parser._update_statistics(entry)
        self.assertEqual(self.parser.top_queried_domains["popular.com"], 2)


class TestLogParserParseLogs(unittest.TestCase):
    """Tests for the parse_logs method."""

    def test_returns_none_when_file_missing(self):
        parser = LogParser("/nonexistent/path.log", {})
        result = parser.parse_logs()
        self.assertIsNone(result)

    def test_parses_multiple_lines(self):
        lines = "\n".join([
            json.dumps({"client_ip": f"10.0.0.{i}", "qname": f"sub{i}.example.com", "qtype": "A", "category": "real"})
            for i in range(3)
        ])
        parser = LogParser("fake.log", {})
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=lines)):
                result = parser.parse_logs()
        self.assertEqual(len(result), 3)


class TestLogParserApplyDetectionRules(unittest.TestCase):
    """Tests for the _apply_detection_rules method."""

    def setUp(self):
        self.parser = LogParser("dummy.log", {
            "admin_query": 20,
            "vpn_query": 15,
            "db_query": 25,
            "fake_subdomain_query": 10,
        })

    def test_admin_keyword_triggers_rule(self):
        entry = {"qname": "admin.internal.example.com", "is_honeypot_hit": True, "is_dynamic": False}
        stats = {"threat_score": 0}
        self.parser._apply_detection_rules(entry, stats)
        self.assertEqual(stats["threat_score"], 20)

    def test_sql_keyword_maps_to_db_query(self):
        entry = {"qname": "sql.example.com", "is_honeypot_hit": True, "is_dynamic": False}
        stats = {"threat_score": 0}
        self.parser._apply_detection_rules(entry, stats)
        self.assertEqual(stats["threat_score"], 25)

    def test_multiple_keywords_accumulate(self):
        entry = {"qname": "admin-vpn.example.com", "is_honeypot_hit": True, "is_dynamic": False}
        stats = {"threat_score": 0}
        self.parser._apply_detection_rules(entry, stats)
        self.assertEqual(stats["threat_score"], 35)  # 20 (admin) + 15 (vpn)

    def test_no_keyword_no_score_change(self):
        entry = {"qname": "www.example.com", "is_honeypot_hit": True, "is_dynamic": False}
        stats = {"threat_score": 5}
        self.parser._apply_detection_rules(entry, stats)
        self.assertEqual(stats["threat_score"], 5)


class TestValidateLogFilePath(unittest.TestCase):
    """Tests for the validate_log_file_path function."""

    def test_path_traversal_blocked(self):
        result = validate_log_file_path("../../etc/passwd")
        self.assertIsNone(result)

    def test_path_outside_logs_dir_blocked(self):
        # A path that resolves outside the logs/ directory should be blocked
        # even if the file exists. Use a path that is definitely outside logs/.
        result = validate_log_file_path("../../etc/shadow")
        self.assertIsNone(result)

    def test_valid_path_in_logs_dir(self):
        with patch("os.path.exists", return_value=True):
            with patch("os.path.isfile", return_value=True):
                result = validate_log_file_path("logs/honeyresolver.log")
        self.assertIsNotNone(result)
        self.assertIn("logs", result)


# ===========================================================================
# ThreatIntelClient
# ===========================================================================
class TestThreatIntelClient(unittest.TestCase):
    """Tests for ThreatIntelClient."""

    def test_initialisation(self):
        client = ThreatIntelClient()
        self.assertIsNotNone(client)

    @patch("requests.get")
    def test_get_ip_reputation_returns_dict(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"data": {"abuseConfidenceScore": 0, "totalReports": 0}},
        )
        client = ThreatIntelClient()
        result = client.get_ip_reputation("8.8.8.8")
        self.assertIsInstance(result, dict)

    @patch("requests.get", side_effect=Exception("Network error"))
    def test_get_ip_reputation_handles_exception(self, _mock):
        client = ThreatIntelClient()
        result = client.get_ip_reputation("8.8.8.8")
        # Should return a dict with an error key or empty, not raise
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
