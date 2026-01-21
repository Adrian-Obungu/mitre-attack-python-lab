import pytest
from unittest.mock import patch, MagicMock
import platform
import psutil

from src.defense_evasion.defense_impairment_detector import T1562DefenseImpairmentDetector

@pytest.fixture
def detector():
    return T1562DefenseImpairmentDetector()

def test_detector_initialization(detector):
    assert detector is not None
    assert detector.platform == platform.system()

@patch('psutil.win_service_get')
def test_check_security_services_windows_running(mock_win_service_get, detector):
    if platform.system() != "Windows":
        pytest.skip("Windows-specific test")

    mock_service = MagicMock()
    mock_service.status.return_value = 'running'
    mock_win_service_get.return_value = mock_service

    stopped = detector.check_security_services()
    assert len(stopped) == 0

@patch('psutil.win_service_get')
def test_check_security_services_windows_stopped(mock_win_service_get, detector):
    if platform.system() != "Windows":
        pytest.skip("Windows-specific test")

    mock_service = MagicMock()
    mock_service.status.return_value = 'stopped'
    mock_win_service_get.return_value = mock_service

    stopped = detector.check_security_services()
    assert len(stopped) > 0
    assert "WinDefend" in stopped

@patch('os.system')
def test_check_security_services_linux_running(mock_os_system, detector):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific test")
    
    # Mock os.system to return 0 (service is running)
    mock_os_system.return_value = 0
    detector.platform = "Linux"
    stopped = detector.check_security_services()
    assert len(stopped) == 0

@patch('os.system')
def test_check_security_services_linux_stopped(mock_os_system, detector):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific test")

    # Mock os.system to return non-zero (service is stopped)
    mock_os_system.return_value = 1
    detector.platform = "Linux"
    stopped = detector.check_security_services()
    assert len(stopped) > 0
    assert "auditd" in stopped

@patch('os.path.exists')
@patch('os.path.getsize')
def test_check_tool_tampering(mock_getsize, mock_exists, detector):
    mock_exists.return_value = True
    mock_getsize.return_value = 20000 # > 10KB

    indicators = detector.check_tool_tampering()
    assert len(indicators) == 1
    assert indicators[0]["indicator"] == "hosts_file_large"

@patch('os.path.exists')
def test_check_log_integrity(mock_exists, detector):
    mock_exists.return_value = False # Simulate missing log file
    
    issues = detector.check_log_integrity()
    assert len(issues) > 0
    assert issues[0]["indicator"] == "log_file_missing"

def test_check_security_services_unsupported_os(detector):
    detector.platform = "UnsupportedOS"
    stopped = detector.check_security_services()
    assert len(stopped) == 0

@patch('psutil.win_service_get', side_effect=psutil.NoSuchProcess(pid=123, name='test'))
def test_check_security_services_no_such_process(mock_win_service_get, detector):
    if platform.system() != "Windows":
        pytest.skip("Windows-specific test")
    
    stopped = detector.check_security_services()
    assert len(stopped) > 0
    assert "WinDefend" in stopped

@patch('os.path.exists', return_value=False)
def test_check_tool_tampering_no_hosts_file(mock_exists, detector):
    indicators = detector.check_tool_tampering()
    assert len(indicators) == 0

@patch('os.path.exists', return_value=True)
@patch('os.path.getsize', return_value=100)
def test_check_tool_tampering_small_hosts_file(mock_getsize, mock_exists, detector):
    indicators = detector.check_tool_tampering()
    assert len(indicators) == 0

@patch('os.path.exists', return_value=True)
def test_check_log_integrity_log_exists(mock_exists, detector):
    issues = detector.check_log_integrity()
    assert len(issues) == 0

@patch('os.system', side_effect=Exception("Test Exception"))
def test_get_linux_service_status_exception(mock_os_system, detector):
    if platform.system() != "Linux":
        pytest.skip("Linux-specific test")
    detector.platform = "Linux"
    status = detector._get_linux_service_status("test")
    assert status is None

@patch('psutil.win_service_get', side_effect=Exception("Generic Error"))
def test_check_security_services_windows_exception(mock_win_service_get, detector):
    if platform.system() != "Windows":
        pytest.skip("Windows-specific test")
    
    stopped = detector.check_security_services()
    assert len(stopped) == 0 # No services explicitly added as "stopped" if exception occurs

def test_check_tool_tampering_unsupported_os(detector):
    with patch('platform.system', return_value='UnsupportedOS'):
        detector.platform = "UnsupportedOS"
        indicators = detector.check_tool_tampering()
        assert indicators == []

@patch('os.path.exists', return_value=True)
@patch('os.path.getsize', side_effect=Exception("Size error"))
def test_check_tool_tampering_getsize_exception(mock_getsize, mock_exists, detector):
    indicators = detector.check_tool_tampering()
    assert indicators == []

def test_check_log_integrity_unsupported_os(detector):
    with patch('platform.system', return_value='UnsupportedOS'):
        detector.platform = "UnsupportedOS"
        issues = detector.check_log_integrity()
        assert issues == []
