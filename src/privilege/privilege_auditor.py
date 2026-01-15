import os
import sys
import logging
import json
import argparse
import subprocess # Added for scheduled tasks and UAC bypass checks
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional

# Import helper modules
try:
    # Absolute import for when running as a package
    from src.privilege.path_hijack_detector import PathHijackDetector
    from src.privilege.service_scanner import ServiceScanner
    from src.privilege.logon_script_detector import LogonScriptDetector
except ImportError:
    # Relative import for when running as a standalone script
    from path_hijack_detector import PathHijackDetector
    from service_scanner import ServiceScanner
    from logon_script_detector import LogonScriptDetector

# Conditional import for winreg - only available on Windows
try:
    import winreg
except ImportError:
    winreg = None
# Setup basic logging for the module
# This will be overridden by structured JSON logging in main application
import logging
logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    logger.warning("winreg module not available. Registry-based checks might be limited on this system.")

# Setup basic logging for the module
# This will be overridden by structured JSON logging in main application
if not logger.handlers:
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

@dataclass
class PrivilegeFinding:
    """
    Represents a single privilege escalation finding.
    """
    technique_id: str          # e.g., "T1037"
    technique_name: str        # e.g., "Logon Scripts"
    description: str
    risk_level: str            # LOW, MEDIUM, HIGH, CRITICAL
    evidence: str
    mitigation: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    details: Optional[Dict[str, Any]] = None

class PrivilegeAuditor:
    """
    Audits for common Windows privilege escalation vectors.
    """
    def __init__(self, allowlist_path: str = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'privilege_allowlist.json')):
        self.allowlist = self._load_allowlist(allowlist_path)
        self.findings: List[PrivilegeFinding] = []
        self._setup_logging()
        self.path_hijack_detector = PathHijackDetector()
        self.service_scanner = ServiceScanner()


    def scan(self):
        """
        Execute comprehensive privilege escalation scan
        
        Returns:
            List of PrivilegeFinding objects
        """
        findings = []
        
        try:
            # Check for path hijacking
            path_findings = self.path_hijack_detector.scan()
            findings.extend(path_findings)
            
            # Check service permissions
            service_findings = self.service_scanner.scan()
            findings.extend(service_findings)
            
            # Check logon scripts
            logon_detector = LogonScriptDetector()
            logon_findings = logon_detector.scan()
            findings.extend(logon_findings)
            
        except Exception as e:
            logger.error(f"Error during privilege scan: {e}")
            
        return findings

    def _setup_logging(self):
        """Sets up structured JSON logging for the auditor."""
        # Check if already configured by a parent (e.g., API server)
        if not any(isinstance(h, JsonFormatter) for h in logger.handlers):
            logger.handlers.clear()
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(JsonFormatter())
            logger.addHandler(console_handler)
            logger.setLevel(logging.INFO) # Default level

    def _load_allowlist(self, path: str) -> Dict[str, Any]:
        """Loads the allowlist from a JSON file."""
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding privilege allowlist JSON from {path}: {e}")
                return {}
        logger.info(f"Privilege allowlist not found at {path}. Proceeding without allowlist.")
        return {}

    def _is_windows(self) -> bool:
        """Checks if the current operating system is Windows."""
        return os.name == 'nt'

    def detect_logon_script_persistence(self) -> List[PrivilegeFinding]:
        """
        Detects persistence via Windows logon scripts in the Registry (T1037).
        """
        findings = []
        if not self._is_windows() or not winreg:
            logger.info("Skipping logon script persistence check: Not on Windows or winreg not available.")
            return findings

        # Common Run/RunOnce keys for user and local machine
        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"), # 32-bit apps on 64-bit Windows
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        logger.info("Detecting logon script persistence...")
        for hkey_root, subkey_path in run_keys:
            try:
                with winreg.OpenKey(hkey_root, subkey_path) as key:
                    i = 0
                    while True:
                        try:
                            value_name, value_data, value_type = winreg.EnumValue(key, i)
                            if value_name and value_data:
                                # Check against allowlist
                                if subkey_path in self.allowlist.get("logon_scripts", {}):
                                    if value_name in self.allowlist["logon_scripts"][subkey_path]:
                                        logger.debug(f"Logon script '{value_name}' in '{subkey_path}' is allowlisted. Skipping.")
                                        i += 1
                                        continue

                                findings.append(PrivilegeFinding(
                                    technique_id="T1037",
                                    technique_name="Logon Scripts",
                                    description=f"Suspicious logon script detected in {subkey_path}\\{value_name}.",
                                    risk_level="HIGH",
                                    evidence=f"Registry Key: {subkey_path}, Value Name: {value_name}, Value Data: {value_data}",
                                    mitigation="Review the purpose of this logon script. If unauthorized, remove the registry entry.",
                                    details={"key": str(hkey_root) + "\\" + subkey_path, "name": value_name, "data": value_data, "type": value_type}
                                ))
                            i += 1
                        except OSError: # No more values
                            break
            except OSError as e:
                logger.debug(f"Could not open registry key {subkey_path}: {e}")
            except Exception as e:
                logger.error(f"Error accessing registry key {subkey_path}: {e}")
        return findings

    def detect_python_path_hijacking(self) -> List[PrivilegeFinding]:
        """
        Detects potential Python Path Hijacking (T1073.001) vulnerabilities.
        """
        findings = []
        logger.info("Detecting Python Path Hijacking...")
        if not self._is_windows():
            logger.info("Skipping Python Path Hijacking check: Not on Windows.")
            return findings
        
        path_findings = self.path_hijack_detector.run_all_checks()
        for pf in path_findings:
            risk = "HIGH" if pf["is_writable"] and pf["position"] < 5 else "MEDIUM" # Heuristic for risk
            findings.append(PrivilegeFinding(
                technique_id="T1073.001",
                technique_name="Python Path Hijacking",
                description=f"Writable directory '{pf['path']}' found early in system PATH or sys.path.",
                risk_level=risk,
                evidence=f"Path: {pf['path']}, Position: {pf['position']}, Writable: {pf['is_writable']}, Reason: {pf['reason']}",
                mitigation="Remove writable directories from critical system paths, or ensure they are not writable by unprivileged users.",
                details=pf
            ))
        return findings

    def detect_service_misconfigurations(self) -> List[PrivilegeFinding]:
        """
        Detects Windows Service Misconfigurations (T1543.003).
        """
        findings = []
        logger.info("Detecting Windows Service Misconfigurations...")
        if not self._is_windows():
            logger.info("Skipping Windows Service Misconfigurations check: Not on Windows.")
            return findings

        service_findings = self.service_scanner.run_all_checks()
        for sf in service_findings:
            findings.append(PrivilegeFinding(
                technique_id="T1543.003",
                technique_name="Windows Service Misconfigurations",
                description=f"Potential service misconfiguration detected: {sf.get('type', 'Unknown')}",
                risk_level=sf.get('risk_level', 'MEDIUM'),
                evidence=f"Service: {sf.get('service_name', 'N/A')}, Details: {sf.get('evidence', 'N/A')}",
                mitigation=sf.get('mitigation', 'Review service configuration for security vulnerabilities.'),
                details=sf
            ))
        return findings

    def detect_scheduled_task_vulnerabilities(self) -> List[PrivilegeFinding]:
        """
        Detects Scheduled Task Vulnerabilities (T1053.005).
        Looks for tasks with unquoted paths or running as SYSTEM from non-system-owned paths.
        """
        findings = []
        if not self._is_windows():
            logger.info("Skipping scheduled task vulnerabilities check: Not on Windows.")
            return findings

        logger.info("Detecting Scheduled Task Vulnerabilities...")
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/FO", "LIST", "/V"],
                capture_output=True, text=True, check=True
            )
            tasks_raw = result.stdout.strip().split('\n\n')

            for task_block in tasks_raw:
                if not task_block.strip():
                    continue
                task_info = {}
                for line in task_block.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        task_info[key.strip()] = value.strip()
                
                task_name = task_info.get('TaskName', 'UNKNOWN')
                task_to_run = task_info.get('Task To Run', '')
                run_as_user = task_info.get('Run As User', '')

                # Check for unquoted paths
                if ' ' in task_to_run and not (task_to_run.startswith('"') and task_to_run.endswith('"')):
                    findings.append(PrivilegeFinding(
                        technique_id="T1053.005",
                        technique_name="Scheduled Task Vulnerabilities",
                        description=f"Scheduled task '{task_name}' has an unquoted path containing spaces. This can lead to privilege escalation.",
                        risk_level="HIGH",
                        evidence=f"TaskName: {task_name}, Path: {task_to_run}",
                        mitigation="Quote the executable path for the scheduled task.",
                        details=task_info
                    ))
                
                # Further checks can be added here, e.g., running as SYSTEM for non-system executables
                if run_as_user.upper() == 'SYSTEM' and task_to_run and not task_to_run.lower().startswith((r'c:\windows\system32', r'c:\windows\syswow64')):
                    # Check if the path is allowlisted
                    if self.allowlist.get("scheduled_tasks", {}).get(task_name) == task_to_run:
                        logger.debug(f"Scheduled task '{task_name}' with SYSTEM user and non-system path is allowlisted. Skipping.")
                        continue

                    findings.append(PrivilegeFinding(
                        technique_id="T1053.005",
                        technique_name="Scheduled Task Vulnerabilities",
                        description=f"Scheduled task '{task_name}' runs as SYSTEM from a non-system owned path '{task_to_run}'.",
                        risk_level="CRITICAL",
                        evidence=f"TaskName: {task_name}, User: {run_as_user}, Path: {task_to_run}",
                        mitigation="Verify the legitimacy and security of the executable. Ensure only SYSTEM owned executables run as SYSTEM.",
                        details=task_info
                    ))

        except FileNotFoundError:
            logger.error("schtasks command not found. Ensure it's in your PATH.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running schtasks command: {e.stderr}")
        except Exception as e:
            logger.error(f"Error parsing schtasks output: {e}")
        
        return findings

    def detect_uac_bypass(self) -> List[PrivilegeFinding]:
        """
        Detects potential User Account Control (UAC) Bypass (T1548.002) vectors.
        This often involves looking for specific auto-elevated executables or COM objects.
        Placeholder with some basic registry checks for auto-elevated applications.
        """
        findings = []
        if not self._is_windows():
            logger.info("Skipping UAC Bypass check: Not on Windows.")
            return findings
        
        logger.info("Detecting UAC Bypass vulnerabilities (preliminary check)...")

        # Check for Common Auto-Elevated Executables (example list, not exhaustive)
        # These are executables that Microsoft allows to auto-elevate by design
        # and could potentially be abused if their execution flow is hijacked.
        auto_elevated_executables = [
            "CompMgmtLauncher.exe", "Eventvwr.exe", "fodhelper.exe", "sdclt.exe",
            "computerdefaults.exe", "changepk.exe", "dccw.exe", "wsreset.exe",
        ]
        system_path = os.environ.get("SystemRoot", r"C:\Windows")
        potential_uac_bypass_paths = []

        for exe in auto_elevated_executables:
            exe_path = os.path.join(system_path, "System32", exe)
            if os.path.exists(exe_path):
                potential_uac_bypass_paths.append(exe_path)
            exe_path_syswow = os.path.join(system_path, "SysWOW64", exe)
            if os.path.exists(exe_path_syswow):
                potential_uac_bypass_paths.append(exe_path_syswow)

        if potential_uac_bypass_paths:
            findings.append(PrivilegeFinding(
                technique_id="T1548.002",
                technique_name="Bypass User Account Control",
                description="Presence of common auto-elevated executables that could be abused for UAC bypass.",
                risk_level="MEDIUM",
                evidence=f"Found auto-elevated executables: {', '.join(potential_uac_bypass_paths)}",
                mitigation="Monitor for suspicious execution of these applications. Ensure system integrity and patch vulnerabilities.",
                details={"executables_found": potential_uac_bypass_paths}
            ))

        # Further checks could involve:
        # - Checking COM object hijacking for specific CLSIDs
        # - Analyzing registry entries for auto-elevated applications (e.g., in HKEY_CURRENT_USER\Software\Classes\...)
        
        return findings


    def run_all_checks(self) -> Dict[str, Any]:
        """
        Runs all privilege escalation checks and aggregates findings into a report.
        """
        self.findings = []
        logger.info("Starting all privilege escalation checks...")

        self.findings.extend(self.detect_logon_script_persistence())
        self.findings.extend(self.detect_python_path_hijacking())
        self.findings.extend(self.detect_service_misconfigurations())
        self.findings.extend(self.detect_scheduled_task_vulnerabilities())
        self.findings.extend(self.detect_uac_bypass()) # Add UAC Bypass check

        report = {
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": [f.__dict__ for f in self.findings]
        }
        logger.info("Privilege escalation checks completed.", extra={"report_summary": report["total_findings"]})
        return report

    def save_report(self, filename: str) -> str:
        """
        Saves the aggregated report to a JSON file.
        """
        report_data = self.run_all_checks()
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=4)
        logger.info(f"Privilege escalation report saved to {filename}")
        return filename

    def print_report(self, report: Dict[str, Any]) -> None:
        """
        Prints the report findings to the console in a human-readable format.
        """
        logger.info("\n--- Privilege Escalation Report ---")
        for finding in report["findings"]:
            logger.info(f"Technique ID: {finding['technique_id']} ({finding['technique_name']})")
            logger.info(f"  Risk Level: {finding['risk_level']}")
            logger.info(f"  Description: {finding['description']}")
            logger.info(f"  Evidence: {finding['evidence']}")
            logger.info(f"  Mitigation: {finding['mitigation']}")
            logger.info("-" * 40)
        logger.info(f"Total Findings: {report['total_findings']}")
        logger.info(f"Report Generated: {report['timestamp']}")


# --- Structured JSON Logging Class (Copied from utils/log_parser.py or similar) ---
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "process_id": record.process,
            "thread_id": record.thread,
            "filename": record.filename,
            "lineno": record.lineno,
        }
        if hasattr(record, 'extra') and record.extra is not None: # Capture extra dict for custom fields
            log_record.update(record.extra)
        
        # Add any extra dictionary values passed in record.msg if it's a dict
        if isinstance(record.msg, dict):
            log_record.update(record.msg)
            log_record["message"] = record.msg.get("message", record.getMessage())

        return json.dumps(log_record)

# --- Main execution for CLI ---
def main():
    parser = argparse.ArgumentParser(description="Audit for Windows privilege escalation vectors.")
    parser.add_argument(
        "--report-file",
        "-r",
        type=str,
        default=None,
        help="Specify a file to save the report in JSON format."
    )
    args = parser.parse_args()

    auditor = PrivilegeAuditor()
    report = auditor.run_all_checks()

    if args.report_file:
        auditor.save_report(args.report_file)
    else:
        auditor.print_report(report)

if __name__ == "__main__":
    main()
