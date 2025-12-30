import os
import json
import logging
import platform
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any, Optional

# Conditional import for winreg as it's Windows-specific
if platform.system() == "Windows":
    import winreg
else:
    winreg = None # Placeholder for non-Windows systems

logger = logging.getLogger(__name__)
# Ensure logger is configured to output JSON if that's the project standard,
# or at least a structured format. For now, use basic config.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class PersistenceAuditor:
    """
    Detects common persistence mechanisms on Windows systems and integrates
    into the existing threat analysis pipeline by providing structured JSON reports.
    """

    def __init__(self, allowlist_path: str = "config/persistence_allowlist.json"):
        """
        Initializes the PersistenceAuditor, loading the allowlist.

        Args:
            allowlist_path: Path to the JSON file containing allowlisted persistence entries.
        """
        self.allowlist_path = os.path.join(os.path.dirname(__file__), '..', '..', allowlist_path)
        self.allowlist = self._load_allowlist()
        logger.info(f"PersistenceAuditor initialized. Allowlist loaded from {self.allowlist_path}")

    def _load_allowlist(self) -> Dict[str, List[str]]:
        """
        Loads the persistence allowlist from a JSON file.

        Returns:
            A dictionary containing allowlisted entries categorized by technique.
        """
        try:
            with open(self.allowlist_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Allowlist file not found at {self.allowlist_path}. Proceeding without allowlist.")
            return {
                "registry_autoruns": [],
                "scheduled_tasks": [],
                "wmi_subscriptions": []
            }
        except json.JSONDecodeError:
            logger.error(f"Error decoding JSON from allowlist file {self.allowlist_path}. Check file format.")
            return {
                "registry_autoruns": [],
                "scheduled_tasks": [],
                "wmi_subscriptions": []
            }

    def _is_allowlisted(self, entry_value: str, technique_category: str) -> bool:
        """
        Checks if a given entry value is present in the allowlist for a specific technique category.

        Args:
            entry_value: The value to check (e.g., command path, task name).
            technique_category: The category in the allowlist (e.g., 'registry_autoruns', 'scheduled_tasks').

        Returns:
            True if the entry is allowlisted, False otherwise.
        """
        allowlist_entries = self.allowlist.get(technique_category, [])
        return any(entry_value.lower() in item.lower() for item in allowlist_entries)

    def _assign_risk(self, entry_path: str, is_allowlisted: bool) -> str:
        """
        Assigns a risk level to a persistence entry based on its path and allowlist status.

        Args:
            entry_path: The full path or command associated with the persistence entry.
            is_allowlisted: True if the entry is found in the allowlist.

        Returns:
            A string representing the risk level ('low', 'medium', 'high').
        """
        if is_allowlisted:
            return "low"

        entry_path_lower = entry_path.lower()
        # Common system paths
        system_paths = [
            os.getenv('SYSTEMROOT', 'c:\\windows').lower(),
            os.path.join(os.getenv('PROGRAMFILES', 'c:\\program files')).lower(),
            os.path.join(os.getenv('PROGRAMFILES(X86)', 'c:\\program files (x86)')).lower(),
        ]
        
        # Check if the path is within common system directories
        is_system_path = False
        for sys_path in system_paths:
            if entry_path_lower.startswith(sys_path):
                is_system_path = True
                break
        
        # Check for common "suspicious" user-writable locations
        is_user_writable_path = False
        appdata_path = os.getenv('APPDATA', 'c:\\users\\default\\appdata\\roaming').lower()
        localappdata_path = os.getenv('LOCALAPPDATA', 'c:\\users\\default\\appdata\\local').lower()
        temp_path = os.getenv('TEMP', 'c:\\windows\\temp').lower()

        if appdata_path in entry_path_lower or \
           localappdata_path in entry_path_lower or \
           temp_path in entry_path_lower:
            is_user_writable_path = True

        if is_user_writable_path and not is_system_path:
            return "high" # Unknown entry in a user-writable, non-system path
        elif not is_system_path and not is_user_writable_path:
            return "high" # Unknown entry in a completely custom/non-standard path
        else:
            return "medium" # Unknown entry in a standard system path (could be legitimate software)

    def audit(self) -> List[Dict[str, Any]]:
        """
        Executes all persistence checks and generates a consolidated report.

        Returns:
            A list of dictionaries, where each dictionary represents a detected
            persistence mechanism with its associated risk.
        """
        if platform.system() != "Windows":
            logger.error("Persistence Auditor currently only supports Windows systems.")
            return []

        findings = []
        timestamp = datetime.now().isoformat()

        # Registry Autoruns
        registry_entries = self._get_registry_autoruns()
        for entry in registry_entries:
            is_allowlisted = self._is_allowlisted(entry["value"], "registry_autoruns")
            risk_level = self._assign_risk(entry["value"], is_allowlisted)
            findings.append({
                "timestamp": timestamp,
                "technique": "T1547.001", # Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
                "location": entry["key"],
                "value": entry["value"],
                "risk_level": risk_level,
                "allowlisted": is_allowlisted,
            })
        
        # Scheduled Tasks
        scheduled_tasks = self._get_scheduled_tasks()
        for task in scheduled_tasks:
            is_allowlisted = self._is_allowlisted(task["task_name"], "scheduled_tasks") or \
                             self._is_allowlisted(task["command"], "scheduled_tasks")
            risk_level = self._assign_risk(task["command"], is_allowlisted)
            findings.append({
                "timestamp": timestamp,
                "technique": "T1053.005", # Scheduled Task/Job: Scheduled Task
                "location": task["task_name"],
                "value": task["command"],
                "risk_level": risk_level,
                "allowlisted": is_allowlisted,
                "creator": task.get("creator")
            })

        # WMI Event Subscriptions
        wmi_subscriptions = self._get_wmi_event_subscriptions()
        for sub in wmi_subscriptions:
            is_allowlisted = self._is_allowlisted(sub["consumer_command"], "wmi_subscriptions")
            risk_level = self._assign_risk(sub["consumer_command"], is_allowlisted)
            findings.append({
                "timestamp": timestamp,
                "technique": "T1546.003", # Event Triggered Execution: Windows Management Instrumentation
                "location": f"WMI Event ID {sub['event_id']} (Filter: {sub['filter_query']})",
                "value": sub["consumer_command"],
                "risk_level": risk_level,
                "allowlisted": is_allowlisted,
                "event_id": sub["event_id"],
                "filter_query": sub["filter_query"]
            })

        return findings

    # --- Persistence Check Methods (to be implemented) ---

    def _get_registry_autoruns(self) -> List[Dict[str, str]]:
        """
        Retrieves entries from common Windows Registry Run/RunOnce keys.
        """
        if winreg is None:
            logger.error("winreg module not available. Cannot perform registry checks.")
            return []

        autorun_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        registry_entries = []
        for hkey, subkey in autorun_keys:
            try:
                with winreg.OpenKey(hkey, subkey) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            registry_entries.append({"key": f"{hkey}\\{subkey}", "name": name, "value": value})
                            i += 1
                        except OSError: # No more values
                            break
            except OSError as e:
                logger.debug(f"Could not open registry key {hkey}\\{subkey}: {e}")
            except Exception as e:
                logger.error(f"Error reading registry key {hkey}\\{subkey}: {e}")
        return registry_entries

    def _get_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """
        Retrieves information about scheduled tasks using schtasks.
        """
        try:
            # schtasks /query /v /fo csv /nh -> verbose, csv format, no headers
            result = subprocess.run(
                ["schtasks", "/query", "/v", "/fo", "csv", "/nh"],
                capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore'
            )
            tasks_csv = result.stdout.strip()
            
            # Manually parse CSV to handle potential issues with CSV module and subprocess
            # Expected format: HostName,TaskName,Next Run Time,Status,Logon Mode,Last Run Time,Last Result,Author,Run As User,Task To Run,Start In,Comment,Scheduled Task State,Idle Time,Power Management,Run As User,Delete Task If Not Run,Run For,Repeat: Every,Repeat: Until: Time,Repeat: Until: Date,Schedule,Schedule Type,Start Date,Start Time,Months,Days,Day of Week,Weeks,Enabled,Run Online,Hidden,Run X times,Delete Task After X times
            # We are interested in TaskName, Author, Task To Run (command)
            
            # Simplified parsing - relies on stable field order from schtasks /query /v /fo csv
            # We need to find the indices of "TaskName", "Author", "Task To Run"
            # Since /nh is used, we have to assume the order or parse headers if not /nh.
            # Based on documentation and typical output:
            # Index 1: TaskName, Index 7: Author, Index 9: Task To Run (command)
            scheduled_tasks = []
            for line in tasks_csv.splitlines():
                if not line.strip():
                    continue
                parts = line.split('","') # Split by "," to handle quoted fields
                
                # Clean up quotes from parts
                parts = [p.strip('"') for p in parts]

                try:
                    task_name = parts[1]
                    author = parts[7]
                    command = parts[9]
                    scheduled_tasks.append({
                        "task_name": task_name,
                        "creator": author,
                        "command": command
                    })
                except IndexError:
                    logger.warning(f"Failed to parse scheduled task line: {line[:100]}...")
            
            return scheduled_tasks
        except subprocess.CalledProcessError as e:
            logger.error(f"Error querying scheduled tasks: {e.stderr}")
            return []
        except FileNotFoundError:
            logger.error("schtasks command not found. Cannot perform scheduled task checks.")
            return []

    def _get_wmi_event_subscriptions(self) -> List[Dict[str, str]]:
        """
        Retrieves WMI permanent event subscriptions from the Microsoft-Windows-WMI-Activity/Operational log.
        Looks for Event ID 5861 (WMI Permanent Event Consumer registration).
        """
        try:
            # Query the Windows Event Log for WMI activity related to subscription creation
            # filter by Event ID 5861 (WMI Permanent Event Consumer registration)
            # /f:xml for XML output, /c:1 for 1 event (or higher, but we need all)
            # /q for query
            # /e for event ID
            # This is complex as we need to find the Filter and Consumer
            # A more direct approach might be to query WMI classes directly via PowerShell or wmic/wbemtest
            
            # Alternative: Use wevtutil to query the log for event 5861 and parse the XML
            command = [
                "wevtutil", "qe", "Microsoft-Windows-WMI-Activity/Operational",
                "/q:*[System[(EventID=5861)]]", "/f:xml", "/c:1000" # Max 1000 events
            ]
            result = subprocess.run(
                command, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore'
            )
            event_xml = result.stdout.strip()

            subscriptions = []
            root = ET.fromstring(f"<Events>{event_xml}</Events>") # Wrap in <Events> for valid XML
            for event in root.findall(".//Event"):
                event_id = event.findtext(".//EventID")
                
                if event_id == "5861":
                    consumer_command = "N/A"
                    filter_query = "N/A"

                    # Extract properties from EventData
                    for data in event.findall(".//EventData/Data"):
                        name = data.get("Name")
                        if name == "ConsumerCommandLineTemplate":
                            consumer_command = data.text
                        elif name == "FilterQuery":
                            filter_query = data.text

                    # Also look for the 'Destination' property in newer WMI activity logs
                    # This might be in different places depending on the WMI consumer type
                    # For ActiveScriptEventConsumer, the script text might be in Arguments
                    
                    # More robust parsing would involve looking for
                    # <Property Name="ConsumerCommandLineTemplate">...</Property>
                    # <Property Name="FilterQuery">...</Property>
                    # <Property Name="ConsumerName">...</Property>
                    # This information is typically within <EventData> properties.

                    # For simplicity, we are capturing common command line consumer.
                    if consumer_command != "N/A":
                        subscriptions.append({
                            "event_id": event_id,
                            "filter_query": filter_query,
                            "consumer_command": consumer_command
                        })
                
            return subscriptions
        except subprocess.CalledProcessError as e:
            logger.error(f"Error querying WMI Event Log: {e.stderr}")
            return []
        except FileNotFoundError:
            logger.error("wevtutil command not found. Cannot perform WMI event subscription checks.")
            return []
        except ET.ParseError as e:
            logger.error(f"Error parsing WMI Event Log XML: {e}")
            return []

if __name__ == "__main__":
    auditor = PersistenceAuditor()
    report = auditor.audit()
    print(json.dumps(report, indent=2))
