import pytest
import unittest.mock
import platform
import os
import sys
import json
from datetime import datetime

# Adjust path to import PersistenceAuditor
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.persistence.persistence_auditor import PersistenceAuditor

# Mock data for Windows-specific functions
MOCK_REGISTRY_RUN_KEYS = {
    (unittest.mock.ANY, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"): {
        "SecurityHealth": "C:\\Windows\\system32\\SecurityHealthSystray.exe",
        "OneDrive": "C:\\Users\\User\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background",
    },
    (unittest.mock.ANY, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"): {},
    (unittest.mock.ANY, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"): {},
    (unittest.mock.ANY, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"): {},
    (unittest.mock.ANY, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"): {}, # AppInit_DLLs
    (unittest.mock.ANY, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"): {}, # 32-bit Run key
}

MOCK_SCHTASKS_CSV = """
"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Run As User","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Run","Run For","Repeat: Every","Repeat: Until: Time","Repeat: Until: Date","Schedule","Schedule Type","Start Date","Start Time","Months","Days","Day of Week","Weeks","Enabled","Run Online","Hidden","Run X times","Delete Task After X times"
"DESKTOP-123","\Microsoft\Windows\Setup\SetupUIGuard","N/A","Ready","Interactive/Background","N/A","0","Microsoft","NT AUTHORITY\SYSTEM","C:\\Windows\\system32\\SetupUIGuard.exe","C:\\Windows\\System32\\","","Enabled","PT10M","","","False","0",,"","","At system startup","On startup","","","","","","","True","False","False","0","False"
"DESKTOP-123","\AdobeAAMUpdater-1.0-Microsoft\AdobeARM","N/A","Ready","Interactive/Background","N/A","0","Adobe","User","C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe","C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\","","Enabled","PT1H","","","False","0",,"","","Daily","Daily","1/1/2023","12:00:00 AM","","","","","True","False","False","0","False"
"DESKTOP-123","\MyMaliciousTask","N/A","Ready","Interactive/Background","N/A","0","User","User","C:\\Users\\User\\AppData\\Roaming\\Malware\\malware.exe -arg","C:\\Users\\User\\AppData\\Roaming\\Malware\\","Malicious persistence","Enabled","PT1H","","","False","0",,"","","Daily","Daily","1/1/2023","12:00:00 AM","","","","","True","False","False","0","False"
"""

MOCK_WMI_EVENT_XML = f"""
<Events>
    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
        <System>
            <EventID>5861</EventID>
            <TimeCreated SystemTime='{datetime.now().isoformat()}'/>
            <Provider Name='Microsoft-Windows-WMI-Activity' Guid='{{123-abc}}'/>
        </System>
        <EventData>
            <Data Name='ConsumerCommandLineTemplate'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -Enc {{'base64_encoded_command'}}</Data>
            <Data Name='FilterQuery'>SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.State = 'Stopped' AND NOT TargetInstance.Name = 'winmgmt'</Data>
            <Data Name='ConsumerName'>ServiceStopConsumer</Data>
        </EventData>
    </Event>
    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
        <System>
            <EventID>5861</EventID>
            <TimeCreated SystemTime='{datetime.now().isoformat()}'/>
            <Provider Name='Microsoft-Windows-WMI-Activity' Guid='{{123-abc}}'/>
        </System>
        <EventData>
            <Data Name='ConsumerCommandLineTemplate'>C:\\Users\\Public\\malware.exe</Data>
            <Data Name='FilterQuery'>SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.ExecutablePath LIKE '%bad.exe%'</Data>
            <Data Name='ConsumerName'>MaliciousConsumer</Data>
        </EventData>
    </Event>
</Events>"""

@pytest.fixture
def mock_persistence_auditor():
    """Fixture to create a PersistenceAuditor instance with a mock allowlist."""
    mock_allowlist = {
        "registry_autoruns": ["SecurityHealthSystray.exe", "RtkAudUService64.exe"],
        "scheduled_tasks": ["AdobeAAMUpdater-1.0-Microsoft\AdobeARM"],
        "wmi_subscriptions": ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"]
    }
    with unittest.mock.patch('builtins.open', unittest.mock.mock_open(read_data=json.dumps(mock_allowlist))):
        auditor = PersistenceAuditor(allowlist_path="config/persistence_allowlist.json")
    return auditor

class TestPersistenceAuditor:

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_load_allowlist(self, mock_persistence_auditor):
        """Test that the allowlist is loaded correctly."""
        auditor = mock_persistence_auditor
        assert "registry_autoruns" in auditor.allowlist
        assert "scheduled_tasks" in auditor.allowlist
        assert "wmi_subscriptions" in auditor.allowlist
        assert "SecurityHealthSystray.exe" in auditor.allowlist["registry_autoruns"]

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    @unittest.mock.patch('src.persistence.persistence_auditor.winreg')
    def test_get_registry_autoruns(self, mock_winreg, mock_persistence_auditor):
        """Test _get_registry_autoruns method."""
        # Mocking winreg requires a bit more setup if we want to return specific values
        # For a basic test, we can just ensure it tries to open keys
        auditor = mock_persistence_auditor
        auditor._get_registry_autoruns()
        # Assert that OpenKey was called for expected keys
        assert mock_winreg.OpenKey.called

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    @unittest.mock.patch('subprocess.run')
    def test_get_scheduled_tasks(self, mock_subprocess_run, mock_persistence_auditor):
        """Test _get_scheduled_tasks method."""
        mock_subprocess_run.return_value.stdout = MOCK_SCHTASKS_CSV
        mock_subprocess_run.return_value.stderr = ""
        mock_subprocess_run.return_value.check_returncode = lambda: None # Mock check=True
        auditor = mock_persistence_auditor
        tasks = auditor._get_scheduled_tasks()
        assert len(tasks) == 3
        assert any("AdobeARM.exe" in task["command"] for task in tasks)
        assert any("malware.exe" in task["command"] for task in tasks)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    @unittest.mock.patch('subprocess.run')
    def test_get_wmi_event_subscriptions(self, mock_subprocess_run, mock_persistence_auditor):
        """Test _get_wmi_event_subscriptions method."""
        mock_subprocess_run.return_value.stdout = MOCK_WMI_EVENT_XML
        mock_subprocess_run.return_value.stderr = ""
        mock_subprocess_run.return_value.check_returncode = lambda: None # Mock check=True
        auditor = mock_persistence_auditor
        subscriptions = auditor._get_wmi_event_subscriptions()
        assert len(subscriptions) == 2
        assert any("powershell.exe" in sub["consumer_command"] for sub in subscriptions)
        assert any("malware.exe" in sub["consumer_command"] for sub in subscriptions)

    @pytest.mark.parametrize("value, category, expected", [
        ("SecurityHealthSystray.exe", "registry_autoruns", True),
        ("C:\\Windows\\system32\\NonExistent.exe", "registry_autoruns", False),
        ("malware.exe", "scheduled_tasks", False),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "wmi_subscriptions", True),
    ])
    def test_is_allowlisted(self, mock_persistence_auditor, value, category, expected):
        """Test _is_allowlisted method."""
        auditor = mock_persistence_auditor
        assert auditor._is_allowlisted(value, category) == expected

    @pytest.mark.parametrize("path, is_allowlisted, expected_risk", [
        ("C:\\Windows\\system32\\SecurityHealthSystray.exe", True, "low"),
        ("C:\\Windows\\system32\\LegitApp.exe", False, "medium"), # System path, but not allowlisted
        ("C:\\Program Files\\Common\\GoodApp\\app.exe", False, "medium"), # Program Files, not allowlisted
        ("C:\\Users\\User\\AppData\\Local\\Evil.exe", False, "high"), # AppData, not allowlisted
        ("D:\\Custom\\Malware\\mal.exe", False, "high"), # Non-system, custom path, not allowlisted
    ])
    def test_assign_risk(self, mock_persistence_auditor, path, is_allowlisted, expected_risk):
        """Test _assign_risk method."""
        auditor = mock_persistence_auditor
        assert auditor._assign_risk(path, is_allowlisted) == expected_risk

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    @unittest.mock.patch('src.persistence.persistence_auditor.PersistenceAuditor._get_registry_autoruns')
    @unittest.mock.patch('src.persistence.persistence_auditor.PersistenceAuditor._get_scheduled_tasks')
    @unittest.mock.patch('src.persistence.persistence_auditor.PersistenceAuditor._get_wmi_event_subscriptions')
    def test_audit_method(self, mock_get_wmi, mock_get_scheduled, mock_get_registry, mock_persistence_auditor):
        """Test the main audit method."""
        mock_get_registry.return_value = [
            {"key": "HKLM\Run", "name": "SystemApp", "value": "C:\\Windows\\System32\\SystemApp.exe"},
            {"key": "HKCU\Run", "name": "UserApp", "value": "C:\\Users\\User\\AppData\\Local\\UserApp.exe"},
            {"key": "HKLM\Run", "name": "SecurityHealth", "value": "C:\\Windows\\system32\\SecurityHealthSystray.exe"},
        ]
        mock_get_scheduled.return_value = [
            {"task_name": "\Microsoft\Windows\Setup\SetupUIGuard", "creator": "Microsoft", "command": "C:\\Windows\\system32\\SetupUIGuard.exe"},
            {"task_name": "\MyMaliciousTask", "creator": "User", "command": "C:\\Users\\User\\AppData\\Roaming\\Malware\\malware.exe"},
        ]
        mock_get_wmi.return_value = [
            {"event_id": "5861", "filter_query": "Filter1", "consumer_command": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            {"event_id": "5861", "filter_query": "MaliciousFilter", "consumer_command": "C:\\ProgramData\\evil.exe"},
        ]

        auditor = mock_persistence_auditor
        report = auditor.audit()

        assert len(report) == 7

        # Check for specific entries and risk levels
        assert any(entry["risk_level"] == "low" and "SecurityHealthSystray.exe" in entry["value"] for entry in report)
        assert any(entry["risk_level"] == "medium" and "SystemApp.exe" in entry["value"] for entry in report)
        assert any(entry["risk_level"] == "high" and "UserApp.exe" in entry["value"] for entry in report)
        assert any(entry["risk_level"] == "high" and "malware.exe" in entry["value"] for entry in report)
        assert any(entry["risk_level"] == "high" and "evil.exe" in entry["value"] for entry in report)
