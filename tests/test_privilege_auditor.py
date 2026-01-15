import unittest
import os
import sys
import json
import logging
from unittest.mock import patch, MagicMock
from datetime import datetime

# Dynamically adjust sys.path for script execution
if __name__ == "__main__" and __package__ is None:
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_script_dir, '..', '..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

# Import the module to be tested
from src.privilege.privilege_auditor import PrivilegeAuditor, PrivilegeFinding, JsonFormatter
from src.privilege.path_hijack_detector import PathHijackDetector
from src.privilege.service_scanner import ServiceScanner

# Conditional import for winreg - only available on Windows
try:
    import winreg
except ImportError:
    winreg = None

class TestPrivilegeAuditor(unittest.TestCase):

    def setUp(self):
        # Create a dummy allowlist file for testing
        self.dummy_allowlist_path = 'dummy_privilege_allowlist.json'
        with open(self.dummy_allowlist_path, 'w') as f:
            json.dump({
                "logon_scripts": {
                    r"Software\Microsoft\Windows\CurrentVersion\Run": {
                        "SafeApp": "C:\\SafeApp\\SafeApp.exe"
                    }
                }
            }, f)
        self.auditor = PrivilegeAuditor(allowlist_path=self.dummy_allowlist_path)

    def tearDown(self):
        # Clean up the dummy allowlist file
        if os.path.exists(self.dummy_allowlist_path):
            os.remove(self.dummy_allowlist_path)

    @patch('src.privilege.privilege_auditor.os.name', new='nt')
    @unittest.skipUnless(winreg, "winreg module not available (not on Windows)")
    def test_detect_logon_script_persistence_windows(self):
        # Mock winreg.OpenKey and winreg.EnumValue
        with patch('src.privilege.privilege_auditor.winreg.OpenKey') as mock_open_key, \
             patch('src.privilege.privilege_auditor.winreg.EnumValue') as mock_enum_value:
            
            # Simulate a suspicious entry and an allowlisted entry
            mock_enum_value.side_effect = [
                ("MaliciousApp", "C:\\BadApp\\malicious.exe", winreg.REG_SZ), # Suspicious
                ("SafeApp", "C:\\SafeApp\\SafeApp.exe", winreg.REG_SZ),       # Allowlisted
                OSError # End of enumeration
            ]
            
            # Mock the context manager behavior of OpenKey
            mock_key_handle = MagicMock()
            mock_open_key.return_value.__enter__.return_value = mock_key_handle

            findings = self.auditor.detect_logon_script_persistence()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].technique_id, "T1037")
            self.assertIn("MaliciousApp", findings[0].evidence)
            self.assertNotIn("SafeApp", findings[0].evidence) # Ensure allowlisted is skipped

    @patch('src.privilege.privilege_auditor.os.name', new='posix')
    def test_detect_logon_script_persistence_non_windows(self):
        findings = self.auditor.detect_logon_script_persistence()
        self.assertEqual(len(findings), 0) # Should return empty on non-Windows

    def test_detect_python_path_hijacking(self):
        with patch.object(self.auditor.path_hijack_detector, 'run_all_checks') as mock_run_all_checks:
            mock_run_all_checks.return_value = [
                {"path": "C:\\EvilDir", "position": 0, "is_writable": True, "reason": "Test finding"}
            ]
            
            findings = self.auditor.detect_python_path_hijacking()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].technique_id, "T1073.001")
            self.assertIn("C:\\EvilDir", findings[0].evidence)

    def test_detect_service_misconfigurations(self):
        with patch.object(self.auditor.service_scanner, 'run_all_checks') as mock_run_all_checks:
            mock_run_all_checks.return_value = [
                {"type": "Unquoted Service Path", "description": "Test unquoted path", "evidence": "C:\\Path With Space", "risk_level": "HIGH", "service_name": "TestService"}
            ]

            findings = self.auditor.detect_service_misconfigurations()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].technique_id, "T1543.003")
            self.assertIn("Unquoted Service Path", findings[0].description)

    @patch('src.privilege.privilege_auditor.subprocess.run')
    @patch('src.privilege.privilege_auditor.os.name', new='nt')
    def test_detect_scheduled_task_vulnerabilities_windows(self, mock_subprocess_run):
        # Mocking schtasks output for a vulnerable task
        mock_subprocess_run.return_value = MagicMock(
            stdout='''HostName:                           WIN-P8R042P9H8I
TaskName:                             \Microsoft\Windows\Setup\GWXTriggers\Time-5M
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Batch
Last Run Time:                        N/A
Last Result:                          0
Author:                               Microsoft
Task To Run:                          C:\\Program Files\\Evil Folder\\Evil.exe -arg
Start In:                             N/A
Comment:                              Checks for Windows 10 upgrade eligibility.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop on battery mode
Run As User:                          SYSTEM
Delete Task If Not Run:               Disabled
Run if network available:             No
Run if user logged on:                Yes
Task history:                         Enabled
Folder:                               \Microsoft\Windows\Setup\GWXTriggers
Priority:                             7
Recurrence:                           Daily
Schedule:                             Every 5 minutes, every day
Start Boundary:                       2015-05-20T00:00:00
End Boundary:                         2099-01-01T00:00:00
Task Registration Date:               2015-05-20T10:15:30.000
Task Security Description:
"DACL: (A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;LS)(A;;CCLCSWLOCRRC;;;NS)(A;;GR;;;SY)(A;;GR;;;S-1-5-32-544)(A;;GR;;;RC)"
'''
        )
        findings = self.auditor.detect_scheduled_task_vulnerabilities()
        self.assertEqual(len(findings), 2)


    @patch('src.privilege.privilege_auditor.os.name', new='posix')
    def test_detect_scheduled_task_vulnerabilities_non_windows(self):
        findings = self.auditor.detect_scheduled_task_vulnerabilities()
        self.assertEqual(len(findings), 0)

    def test_run_all_checks(self):
        # Patch all individual detection methods to return mock findings
        with patch.object(self.auditor, 'detect_logon_script_persistence', return_value=[PrivilegeFinding("T1037", "Logon Scripts", "Logon script mock", "HIGH", "mock evidence", "mock mitigation")]), \
             patch.object(self.auditor, 'detect_python_path_hijacking', return_value=[PrivilegeFinding("T1073.001", "Python Path Hijacking", "Path hijack mock", "MEDIUM", "mock evidence", "mock mitigation")]), \
             patch.object(self.auditor, 'detect_service_misconfigurations', return_value=[PrivilegeFinding("T1543.003", "Service Misconfigurations", "Service mock", "CRITICAL", "mock evidence", "mock mitigation")]), \
             patch.object(self.auditor, 'detect_scheduled_task_vulnerabilities', return_value=[PrivilegeFinding("T1053.005", "Scheduled Tasks", "Scheduled task mock", "LOW", "mock evidence", "mock mitigation")]), \
             patch.object(self.auditor, 'detect_uac_bypass', return_value=[PrivilegeFinding("T1548.002", "UAC Bypass", "UAC mock", "HIGH", "mock evidence", "mock mitigation")]) :
            
            report = self.auditor.run_all_checks()
            self.assertEqual(report["total_findings"], 5)
            self.assertEqual(len(report["findings"]), 5)
            self.assertIsInstance(report["timestamp"], str)
            self.assertEqual(report["findings"][0]["technique_id"], "T1037")

    def test_save_report(self):
        with patch.object(self.auditor, 'run_all_checks', return_value={"total_findings": 1, "findings": [{"test": "data"}]}):
            test_filename = "test_report.json"
            saved_file = self.auditor.save_report(test_filename)
            self.assertEqual(saved_file, test_filename)
            self.assertTrue(os.path.exists(test_filename))
            with open(test_filename, 'r') as f:
                content = json.load(f)
                self.assertEqual(content["total_findings"], 1)
            os.remove(test_filename)

    def test_json_formatter(self):
        formatter = JsonFormatter()

        # Mock a LogRecord with extra fields
        mock_record_1 = MagicMock(spec=logging.LogRecord)
        mock_record_1.levelname = "INFO"
        mock_record_1.name = "test_logger"
        mock_record_1.msg = "Test message"
        mock_record_1.args = ()
        mock_record_1.exc_info = None
        mock_record_1.extra = {'custom_field': 'custom_value'}
        mock_record_1.process = 123
        mock_record_1.thread = 456
        mock_record_1.filename = "test_privilege_auditor.py"
        mock_record_1.lineno = 123
        mock_record_1.msecs = 0 # Explicitly set msecs to avoid AttributeError
        mock_record_1.getMessage.return_value = "Test message"
        mock_record_1.created = datetime.now().timestamp() # Needed for formatTime

        # Mock another LogRecord with a dict message
        mock_record_2 = MagicMock(spec=logging.LogRecord)
        mock_record_2.levelname = "INFO"
        mock_record_2.name = "test_logger"
        mock_record_2.msg = {'message': 'Dict message', 'another_field': 123}
        mock_record_2.args = ()
        mock_record_2.exc_info = None
        mock_record_2.extra = None
        mock_record_2.process = 124
        mock_record_2.thread = 457
        mock_record_2.filename = "test_privilege_auditor.py"
        mock_record_2.lineno = 124
        mock_record_2.msecs = 0 # Explicitly set msecs to avoid AttributeError
        mock_record_2.getMessage.return_value = {'message': 'Dict message', 'another_field': 123}
        mock_record_2.created = datetime.now().timestamp() # Needed for formatTime
        
        # Manually format the records using the formatter and then load as JSON
        formatted_log_1 = json.loads(formatter.format(mock_record_1))
        formatted_log_2 = json.loads(formatter.format(mock_record_2))
        
        self.assertEqual(formatted_log_1['message'], "Test message")
        self.assertEqual(formatted_log_1['custom_field'], "custom_value")
        
        self.assertEqual(formatted_log_2['message'], {'message': 'Dict message', 'another_field': 123}['message']) # Directly access message from dict
        self.assertEqual(formatted_log_2['another_field'], 123)


if __name__ == '__main__':
    unittest.main()