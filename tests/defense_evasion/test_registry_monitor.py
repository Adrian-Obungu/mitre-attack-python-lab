import pytest
import platform
from unittest.mock import patch, MagicMock, mock_open

# import winreg is conditional in the source, so we may need to mock it
if platform.system() == "Windows":
    import winreg
else:
    winreg = MagicMock()
    winreg.HKEY_CURRENT_USER = 1
    winreg.HKEY_LOCAL_MACHINE = 2 # Added for non-Windows mocks
    winreg.REG_SZ = 1
    winreg.REG_DWORD = 4


from src.defense_evasion.registry_monitor import T1112RegistryMonitor

@pytest.fixture
def monitor():
    return T1112RegistryMonitor()

def test_monitor_initialization_non_windows(monitor):
    with patch('platform.system', return_value='Linux'):
        m = T1112RegistryMonitor()
        assert m.baseline == {}

def test_scan_persistence_keys_non_windows(monitor):
    with patch('platform.system', return_value='Linux'), \
         patch('src.defense_evasion.registry_monitor.winreg', new=None):
        # Create a new instance of the detector within the mocked environment
        non_windows_monitor = T1112RegistryMonitor()
        results = non_windows_monitor.scan_persistence_keys()
        assert results == {}

def test_compare_snapshots_modified(monitor):
    baseline = {"HKCU_Run": {"test_val": "path1"}}
    current = {"HKCU_Run": {"test_val": "path2"}}
    
    changes = monitor.compare_registry_snapshot(baseline, current)
    
    assert len(changes) == 1
    assert changes[0]['change_type'] == 'modified'

def test_compare_snapshots_removed(monitor):
    baseline = {"HKCU_Run": {"test_val": "path1", "old_val": "path2"}}
    current = {"HKCU_Run": {"test_val": "path1"}}
    
    changes = monitor.compare_registry_snapshot(baseline, current)
    
    assert len(changes) == 1
    assert changes[0]['change_type'] == 'removed'

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch('winreg.OpenKey', side_effect=FileNotFoundError)
def test_get_key_values_file_not_found(mock_open_key, monitor): # Corrected order
    results = monitor._get_key_values(MagicMock(), "path")
    assert results == {}

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch('builtins.open', new_callable=mock_open)
@patch('json.dump')
def test_save_snapshot(mock_json_dump, mock_open_file, monitor):
    keys_to_snapshot = {"HKCU_Run": (winreg.HKEY_CURRENT_USER, "path")}
    monitor.save_snapshot({}, keys_to_snapshot, "test.json")
    mock_json_dump.assert_called_once()

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch('builtins.open', new_callable=mock_open, read_data='{"keys": {"HKCU_Run": ["HKEY_CURRENT_USER", "path"]}, "snapshot": {}}')
@patch('json.load', return_value={"keys": {"HKCU_Run": ["HKEY_CURRENT_USER", "path"]}, "snapshot": {}})
def test_load_snapshot(mock_json_load, mock_open_file, monitor):
    monitor.load_snapshot("test.json")
    mock_json_load.assert_called_once()

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch('builtins.open', side_effect=Exception("Test Exception"))
def test_save_snapshot_exception(mock_open, monitor, tmp_path): # Corrected order
    keys_to_snapshot = {"HKCU_Run": (winreg.HKEY_CURRENT_USER, "path")}
    snapshot_file = tmp_path / "snapshot.json"
    monitor.save_snapshot({}, keys_to_snapshot, str(snapshot_file))

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch('builtins.open', side_effect=FileNotFoundError)
def test_load_snapshot_file_not_found(mock_open, monitor, tmp_path): # Corrected order
    snapshot_file = tmp_path / "snapshot.json"
    result = monitor.load_snapshot(str(snapshot_file))
    assert result == {}

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch('winreg.OpenKey')
@patch('winreg.EnumValue', side_effect=[('Value1', 'Data1', 1), ('Value2', 'Data2', 1), OSError])
@patch('winreg.QueryInfoKey', side_effect=[(2, 0, 0, 0, 0, 0, 0), (0,0,0,0,0,0,0)]) # Mock 2 values
def test_get_key_values_os_error(mock_query_info_key, mock_enum_value, mock_open_key, monitor):
    # Test OSError in _get_key_values
    results = monitor._get_key_values(MagicMock(), "path")
    assert results == {'Value1': 'Data1', 'Value2': 'Data2'}

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch('winreg.OpenKey', side_effect=Exception("Generic Error"))
def test_get_key_values_general_exception(mock_open_key, monitor):
    # Test general Exception in _get_key_values
    results = monitor._get_key_values(MagicMock(), "path")
    assert results == {}

def test_create_registry_snapshot_non_windows(monitor):
    with patch('platform.system', return_value='Linux'), \
         patch('src.defense_evasion.registry_monitor.winreg', new=None):
        non_windows_monitor = T1112RegistryMonitor()
        snapshot = non_windows_monitor.create_registry_snapshot({"key": (MagicMock(), "path")})
        assert snapshot == {}

def test_compare_registry_snapshot_non_windows(monitor):
    with patch('platform.system', return_value='Linux'), \
         patch('src.defense_evasion.registry_monitor.winreg', new=None):
        non_windows_monitor = T1112RegistryMonitor()
        changes = non_windows_monitor.compare_registry_snapshot({}, {})
        assert changes == []

@patch('builtins.open', side_effect=Exception("Test Exception"))
def test_load_snapshot_exception(mock_open, monitor):
    result = monitor.load_snapshot("test.json")
    assert result == {}

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch('winreg.OpenKey')
@patch('winreg.QueryInfoKey', return_value=(0, 1, 0, 0, 0, 0, 0)) # Mock 1 value
@patch('winreg.EnumValue', return_value=('Val1', 'Data1', winreg.REG_SZ))
def test_get_key_values_windows_enum_values(mock_enum_value, mock_query_info_key, mock_open_key, monitor):
    # Test path where EnumValue is successfully called multiple times
    results = monitor._get_key_values(winreg.HKEY_CURRENT_USER, "Software\\TestKey")
    assert results == {'Val1': 'Data1'}

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch('winreg.OpenKey')
@patch('winreg.QueryInfoKey', return_value=(0, 1, 0, 0, 0, 0, 0)) # Mock 1 value
@patch('winreg.EnumValue', return_value=('Val1', 'Data1', winreg.REG_SZ))
def test_create_registry_snapshot_windows_exercising_get_key_values(mock_enum_value, mock_query_info_key, mock_open_key, monitor):
    keys_to_snapshot = {
        "HKCU_Test": (winreg.HKEY_CURRENT_USER, r"Software\Test")
    }
    snapshot = monitor.create_registry_snapshot(keys_to_snapshot)
    assert snapshot == {"HKCU_Test": {'Val1': 'Data1'}}
    mock_open_key.assert_called_once_with(winreg.HKEY_CURRENT_USER, r"Software\Test")
    mock_enum_value.assert_called_once_with(mock_open_key.return_value.__enter__.return_value, 0)

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
def test_compare_registry_snapshot_windows_added_modified_removed(monitor):
    baseline = {
        "HKCU_Run": {
            "ExistingVal": "OldData",
            "RemovedVal": "ToBeRemoved"
        }
    }
    current = {
        "HKCU_Run": {
            "ExistingVal": "NewData",
            "AddedVal": "NewEntry"
        }
    }
    changes = monitor.compare_registry_snapshot(baseline, current)
    
    assert len(changes) == 3
    # Check for modified
    assert any(c['change_type'] == 'modified' and c['value_name'] == 'ExistingVal' for c in changes)
    # Check for added
    assert any(c['change_type'] == 'added' and c['value_name'] == 'AddedVal' for c in changes)
    # Check for removed
    assert any(c['change_type'] == 'removed' and c['value_name'] == 'RemovedVal' for c in changes)