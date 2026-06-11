# -*- coding: utf-8 -*-
"""
Tests for src.compliance.reporter
Covers: ComplianceFramework enum, ComplianceReporter.generate_report,
        get_technique_mapping, export_report (json/csv/markdown),
        and _generate_recommendations.
"""
import csv
import io
import json
import unittest
from datetime import datetime

from src.compliance.reporter import ComplianceReporter, ComplianceFramework


# ---------------------------------------------------------------------------
# Shared sample findings used across multiple test cases
# ---------------------------------------------------------------------------
SAMPLE_FINDINGS = [
    {
        "technique_id": "T1059",
        "severity": "high",
        "details": {"description": "PowerShell execution detected"},
    },
    {
        "technique_id": "T1027",
        "severity": "medium",
        "details": {"description": "Obfuscated script found"},
    },
]

UNKNOWN_FINDING = [
    {
        "technique_id": "T9999",
        "severity": "low",
        "details": {"description": "Unknown technique"},
    }
]


# ===========================================================================
# ComplianceFramework enum
# ===========================================================================
class TestComplianceFrameworkEnum(unittest.TestCase):
    """Tests that the ComplianceFramework enum exposes the expected values."""

    def test_nist_value(self):
        self.assertEqual(ComplianceFramework.NIST_800_53.value, "NIST_800_53")

    def test_cis_value(self):
        self.assertEqual(ComplianceFramework.CIS_CSC_v8.value, "CIS_CSC_v8")

    def test_iso_value(self):
        self.assertEqual(ComplianceFramework.ISO_27001_2022.value, "ISO_27001_2022")

    def test_pci_value(self):
        self.assertEqual(ComplianceFramework.PCI_DSS_v4.value, "PCI_DSS_v4")

    def test_all_four_frameworks_present(self):
        names = {f.name for f in ComplianceFramework}
        self.assertSetEqual(names, {"NIST_800_53", "CIS_CSC_v8", "ISO_27001_2022", "PCI_DSS_v4"})


# ===========================================================================
# ComplianceReporter.get_technique_mapping
# ===========================================================================
class TestGetTechniqueMapping(unittest.TestCase):
    """Tests for the get_technique_mapping helper."""

    def setUp(self):
        self.reporter = ComplianceReporter()

    def test_known_technique_returns_mapping(self):
        mapping = self.reporter.get_technique_mapping("T1059")
        self.assertIsInstance(mapping, dict)
        self.assertIn("NIST_800_53", mapping)

    def test_unknown_technique_returns_empty_dict(self):
        mapping = self.reporter.get_technique_mapping("T9999")
        self.assertEqual(mapping, {})

    def test_t1027_mapped_to_all_frameworks(self):
        mapping = self.reporter.get_technique_mapping("T1027")
        for framework in ("NIST_800_53", "CIS_CSC_v8", "ISO_27001_2022", "PCI_DSS_v4"):
            self.assertIn(framework, mapping)


# ===========================================================================
# ComplianceReporter.generate_report
# ===========================================================================
class TestGenerateReport(unittest.TestCase):
    """Tests for the generate_report method."""

    def setUp(self):
        self.reporter = ComplianceReporter()

    def test_report_has_required_top_level_keys(self):
        report = self.reporter.generate_report(SAMPLE_FINDINGS, ComplianceFramework.NIST_800_53)
        for key in ("metadata", "summary", "by_framework", "recommendations"):
            self.assertIn(key, report)

    def test_metadata_contains_framework_and_date(self):
        report = self.reporter.generate_report(SAMPLE_FINDINGS, ComplianceFramework.CIS_CSC_v8)
        self.assertEqual(report["metadata"]["framework"], "CIS_CSC_v8")
        self.assertIn("report_date", report["metadata"])

    def test_summary_total_findings_matches_input(self):
        report = self.reporter.generate_report(SAMPLE_FINDINGS, ComplianceFramework.NIST_800_53)
        self.assertEqual(report["summary"]["total_findings"], len(SAMPLE_FINDINGS))

    def test_empty_findings_returns_full_compliance(self):
        report = self.reporter.generate_report([], ComplianceFramework.NIST_800_53)
        self.assertEqual(report["summary"]["total_findings"], 0)
        self.assertEqual(report["summary"]["total_controls_mapped"], 0)
        self.assertEqual(report["summary"]["compliance_score"], 100.0)

    def test_known_technique_populates_by_framework(self):
        report = self.reporter.generate_report(SAMPLE_FINDINGS, ComplianceFramework.NIST_800_53)
        self.assertGreater(len(report["by_framework"]), 0)

    def test_unknown_technique_does_not_populate_by_framework(self):
        report = self.reporter.generate_report(UNKNOWN_FINDING, ComplianceFramework.NIST_800_53)
        self.assertEqual(len(report["by_framework"]), 0)

    def test_compliance_score_decreases_with_findings(self):
        report_empty = self.reporter.generate_report([], ComplianceFramework.NIST_800_53)
        report_with_findings = self.reporter.generate_report(SAMPLE_FINDINGS, ComplianceFramework.NIST_800_53)
        self.assertLess(
            report_with_findings["summary"]["compliance_score"],
            report_empty["summary"]["compliance_score"],
        )

    def test_recommendations_list_is_non_empty_with_findings(self):
        report = self.reporter.generate_report(SAMPLE_FINDINGS, ComplianceFramework.NIST_800_53)
        self.assertGreater(len(report["recommendations"]), 0)

    def test_recommendations_mention_control_ids(self):
        report = self.reporter.generate_report(SAMPLE_FINDINGS, ComplianceFramework.NIST_800_53)
        combined = " ".join(report["recommendations"])
        # At least one recommendation should reference a control ID
        self.assertRegex(combined, r"[A-Z]{2,}-\d+|CIS \d+")


# ===========================================================================
# ComplianceReporter.export_report
# ===========================================================================
class TestExportReportJson(unittest.TestCase):
    """Tests for JSON export."""

    def setUp(self):
        self.reporter = ComplianceReporter()
        self.report = self.reporter.generate_report(SAMPLE_FINDINGS, ComplianceFramework.NIST_800_53)

    def test_json_export_is_valid_json(self):
        output = self.reporter.export_report(self.report, "json")
        parsed = json.loads(output)
        self.assertIsInstance(parsed, dict)

    def test_json_export_preserves_metadata(self):
        output = self.reporter.export_report(self.report, "json")
        parsed = json.loads(output)
        self.assertEqual(parsed["metadata"]["framework"], "NIST_800_53")

    def test_json_export_preserves_summary(self):
        output = self.reporter.export_report(self.report, "json")
        parsed = json.loads(output)
        self.assertIn("total_findings", parsed["summary"])


class TestExportReportCsv(unittest.TestCase):
    """Tests for CSV export."""

    def setUp(self):
        self.reporter = ComplianceReporter()
        self.report = self.reporter.generate_report(SAMPLE_FINDINGS, ComplianceFramework.NIST_800_53)

    def test_csv_export_has_header_row(self):
        output = self.reporter.export_report(self.report, "csv")
        reader = csv.reader(io.StringIO(output))
        header = next(reader)
        self.assertIn("Control_ID", header)
        self.assertIn("Technique_ID", header)

    def test_csv_export_has_data_rows(self):
        output = self.reporter.export_report(self.report, "csv")
        rows = list(csv.reader(io.StringIO(output)))
        # Header + at least one data row
        self.assertGreater(len(rows), 1)

    def test_csv_empty_findings_has_only_header(self):
        empty_report = self.reporter.generate_report([], ComplianceFramework.NIST_800_53)
        output = self.reporter.export_report(empty_report, "csv")
        rows = list(csv.reader(io.StringIO(output)))
        self.assertEqual(len(rows), 1)  # Only header


class TestExportReportMarkdown(unittest.TestCase):
    """Tests for Markdown export."""

    def setUp(self):
        self.reporter = ComplianceReporter()
        self.report = self.reporter.generate_report(SAMPLE_FINDINGS, ComplianceFramework.ISO_27001_2022)

    def test_markdown_starts_with_heading(self):
        output = self.reporter.export_report(self.report, "markdown")
        self.assertTrue(output.startswith("# Compliance Report:"))

    def test_markdown_contains_framework_name(self):
        output = self.reporter.export_report(self.report, "markdown")
        self.assertIn("ISO_27001_2022", output)

    def test_markdown_contains_summary_section(self):
        output = self.reporter.export_report(self.report, "markdown")
        self.assertIn("## Summary", output)

    def test_markdown_contains_recommendations_section(self):
        output = self.reporter.export_report(self.report, "markdown")
        self.assertIn("## Recommendations", output)

    def test_markdown_contains_findings_section(self):
        output = self.reporter.export_report(self.report, "markdown")
        self.assertIn("## Findings by Control", output)


class TestExportReportUnsupportedFormat(unittest.TestCase):
    """Tests that unsupported export formats raise ValueError."""

    def test_unsupported_format_raises(self):
        reporter = ComplianceReporter()
        report = reporter.generate_report([], ComplianceFramework.NIST_800_53)
        with self.assertRaises(ValueError):
            reporter.export_report(report, "xml")


# ===========================================================================
# ComplianceReporter._generate_recommendations
# ===========================================================================
class TestGenerateRecommendations(unittest.TestCase):
    """Tests for the _generate_recommendations private method."""

    def setUp(self):
        self.reporter = ComplianceReporter()

    def test_empty_findings_returns_no_gap_message(self):
        recs = self.reporter._generate_recommendations({})
        self.assertEqual(len(recs), 1)
        self.assertIn("No compliance gaps", recs[0])

    def test_one_control_one_recommendation(self):
        findings_by_control = {"SI-3": [{"technique_id": "T1059"}]}
        recs = self.reporter._generate_recommendations(findings_by_control)
        self.assertEqual(len(recs), 1)
        self.assertIn("SI-3", recs[0])

    def test_multiple_controls_multiple_recommendations(self):
        findings_by_control = {
            "SI-3": [{"technique_id": "T1059"}],
            "AC-6": [{"technique_id": "T1027"}, {"technique_id": "T1059"}],
        }
        recs = self.reporter._generate_recommendations(findings_by_control)
        self.assertEqual(len(recs), 2)


if __name__ == "__main__":
    unittest.main()
