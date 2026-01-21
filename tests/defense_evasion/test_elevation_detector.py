import pytest
import platform
from unittest.mock import patch, MagicMock
from src.defense_evasion.elevation_detector import T1548ElevationDetector

@pytest.fixture
def detector():
    return T1548ElevationDetector()

def test_elevation_detector_initialization(detector):
    assert detector is not None

@pytest.mark.skipif(platform.system() != "Windows", reason="UAC is only available on Windows")
def test_check_uac_settings(detector):
    settings = detector.check_uac_settings()
    assert "uac_enabled" in settings

@pytest.mark.skipif(platform.system() != "Windows", reason="This test is for Windows")
@patch('os.path.exists', return_value=True)
def test_scan_auto_elevation_binaries(mock_exists, detector):
    binaries = detector.scan_auto_elevation_binaries()
    assert isinstance(binaries, list)
    assert "fodhelper.exe" in binaries

@patch('psutil.process_iter')
def test_detect_suspicious_parent_chains(mock_process_iter, detector):
    if platform.system() != "Windows":
        pytest.skip("Windows-specific test")
        
    mock_proc = MagicMock()
    mock_proc.pid = 123
    mock_proc.info = {'name': 'powershell.exe', 'ppid': 456}

    mock_parent_proc = MagicMock()
    mock_parent_proc.pid = 456
    mock_parent_proc.info = {'name': 'some_random_process.exe', 'ppid': 789}
    
    mock_process_iter.return_value = [mock_proc, mock_parent_proc]
    
    findings = detector.detect_suspicious_parent_chains()
    assert len(findings) == 1
    assert findings[0]['process_name'] == 'powershell.exe'
    assert findings[0]['parent_name'] == 'some_random_process.exe'

def test_run_checks(detector):
    with patch.object(detector, 'check_uac_settings', return_value={'uac_enabled': True}), \
         patch.object(detector, 'scan_auto_elevation_binaries', return_value=['fodhelper.exe']), \
         patch.object(detector, 'detect_suspicious_parent_chains', return_value=[]):
        
        result = detector.run_checks()
        assert result['uac_enabled'] == True
        assert len(result['auto_elevation_binaries']) == 1
        assert len(result['suspicious_chains']) == 0

def test_check_uac_settings_non_windows(detector):
    with patch('platform.system', return_value='Linux'):
        # Re-initialize detector to pick up mocked platform
        non_windows_detector = T1548ElevationDetector()
        settings = non_windows_detector.check_uac_settings()
        assert settings == {"uac_enabled": "N/A", "details": "UAC check is only for Windows."}

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch('winreg.OpenKey', side_effect=FileNotFoundError)
def test_check_uac_settings_key_not_found(mock_open_key, detector):
    settings = detector.check_uac_settings()
    assert settings == {"uac_enabled": "N/A", "details": "UAC registry keys not found."}

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch('winreg.OpenKey', side_effect=Exception("Test Error"))
def test_check_uac_settings_exception(mock_open_key, detector):
    settings = detector.check_uac_settings()
    assert settings["uac_enabled"] == "N/A"
    assert "Test Error" in settings["details"]

def test_scan_auto_elevation_binaries_non_windows(detector):
    with patch('platform.system', return_value='Linux'):
        non_windows_detector = T1548ElevationDetector()
        binaries = non_windows_detector.scan_auto_elevation_binaries()
        assert binaries == []

def test_detect_suspicious_parent_chains_non_windows(detector):
    with patch('platform.system', return_value='Linux'):
        non_windows_detector = T1548ElevationDetector()
        findings = non_windows_detector.detect_suspicious_parent_chains()
        assert findings == []
