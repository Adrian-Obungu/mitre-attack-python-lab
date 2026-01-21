from enum import Enum
import json
import csv
import io
from datetime import datetime, UTC
from typing import List, Dict, Any

class ComplianceFramework(str, Enum):
    NIST_800_53 = "NIST_800_53"
    CIS_CSC_v8 = "CIS_CSC_v8"
    ISO_27001_2022 = "ISO_27001_2022"
    PCI_DSS_v4 = "PCI_DSS_v4"

class ComplianceReporter:
    _CONTROL_MAPPINGS = {
        'T1070': {
            'NIST_800_53': ['AU-6', 'AU-9', 'SI-4'],
            'CIS_CSC_v8': ['CIS 8.1', 'CIS 8.5'],
            'ISO_27001_2022': ['A.12.4.1', 'A.12.4.3'],
            'PCI_DSS_v4': ['10.2.1', '10.5.5']
        },
        'T1027': {
            'NIST_800_53': ['SI-3', 'SC-3'],
            'CIS_CSC_v8': ['CIS 14.1', 'CIS 14.2'],
            'ISO_27001_2022': ['A.14.2.1'],
            'PCI_DSS_v4': ['6.5.1']
        },
        # Add more mappings as needed
    }

    def __init__(self, test_mode: bool = False):
        self.test_mode = test_mode

    def generate_report(self, findings: List[Dict], framework: ComplianceFramework) -> Dict:
        """
        Generates a compliance report by mapping findings to a specific framework.
        """
        report = {
            "metadata": {
                "report_date": datetime.now(UTC).isoformat(),
                "framework": framework.value,
            },
            "summary": {
                "total_findings": len(findings),
                "total_controls_mapped": 0,
                "compliance_score": 100.0,
            },
            "by_framework": {},
            "recommendations": []
        }
        
        # Placeholder implementation for report generation
        # In a real implementation, this would be much more sophisticated.
        
        mapped_controls = set()
        for finding in findings:
            technique_id = finding.get('technique_id')
            mapping = self.get_technique_mapping(technique_id)
            if mapping and framework.value in mapping:
                controls = mapping[framework.value]
                for control in controls:
                    if control not in report["by_framework"]:
                        report["by_framework"][control] = []
                    report["by_framework"][control].append(finding)
                    mapped_controls.add(control)
        
        report["summary"]["total_controls_mapped"] = len(mapped_controls)
        # Dummy compliance score logic
        if report["summary"]["total_controls_mapped"] > 0:
            report["summary"]["compliance_score"] = round(
                (1 - (len(mapped_controls) / (len(self._CONTROL_MAPPINGS.keys()) * 2))) * 100, 2
            )

        report["recommendations"] = self._generate_recommendations(report["by_framework"])
        
        return report

    def get_technique_mapping(self, technique_id: str) -> Dict[str, List[str]]:
        """Returns the control mappings for a given MITRE ATT&CK technique ID."""
        return self._CONTROL_MAPPINGS.get(technique_id, {})

    def _generate_recommendations(self, findings_by_control: Dict) -> List[str]:
        """Generates high-level recommendations based on failed controls."""
        recommendations = []
        if not findings_by_control:
            return ["No compliance gaps found based on the provided findings."]
        
        for control, findings in findings_by_control.items():
            recommendations.append(f"Review and remediate findings related to control {control} to address {len(findings)} detection(s).")
        return recommendations

    def export_report(self, report: Dict, format: str) -> str:
        """
        Exports the generated report to the specified format.
        """
        if format == 'json':
            return self._export_json(report)
        elif format == 'csv':
            return self._export_csv(report)
        elif format == 'markdown':
            return self._export_markdown(report)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def _export_json(self, report: Dict) -> str:
        """Exports the report to JSON format."""
        return json.dumps(report, indent=2)

    def _export_csv(self, report: Dict) -> str:
        """Exports the report to CSV format."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(["Control_ID", "Technique_ID", "Severity", "Finding_Details"])
        
        for control, findings in report.get("by_framework", {}).items():
            for finding in findings:
                writer.writerow([
                    control,
                    finding.get('technique_id'),
                    finding.get('severity'),
                    json.dumps(finding.get('details', {}))
                ])
                
        return output.getvalue()

    def _export_markdown(self, report: Dict) -> str:
        """Exports the report to Markdown format."""
        md = f"# Compliance Report: {report['metadata']['framework']}\n\n"
        md += f"**Report Date:** {report['metadata']['report_date']}\n\n"
        
        md += "## Summary\n"
        for key, value in report.get("summary", {}).items():
            md += f"- **{key.replace('_', ' ').title()}:** {value}\n"
            
        md += "\n## Findings by Control\n"
        for control, findings in report.get("by_framework", {}).items():
            md += f"### Control: {control}\n"
            for finding in findings:
                md += f"- **Technique:** {finding.get('technique_id')} | **Severity:** {finding.get('severity')}\n"
        
        md += "\n## Recommendations\n"
        for rec in report.get("recommendations", []):
            md += f"- {rec}\n"
            
        return md
