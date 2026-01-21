import pytest
import platform
from unittest.mock import patch, MagicMock, mock_open

from src.discovery.account_discovery import T1087AccountDiscovery

@pytest.fixture
def detector():
    return T1087AccountDiscovery()

def test_initialization(detector):
    assert detector is not None
    assert detector.platform == platform.system()

@patch('src.discovery.account_discovery.os.popen')
def test_run_command_success(mock_popen, detector):
    mock_process = MagicMock()
    mock_process.read.return_value = "line1\nline2\n"
    mock_popen.return_value = mock_process
    
    result = detector._run_command("test command")
    assert result == ["line1", "line2"]
    mock_popen.assert_called_once()
    mock_process.close.assert_called_once()

@patch('src.discovery.account_discovery.os.popen', side_effect=Exception("Test Error"))
def test_run_command_error(mock_popen, detector):
    result = detector._run_command("test command")
    assert result == []
    mock_popen.assert_called_once()

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch.object(T1087AccountDiscovery, '_run_command', return_value=[
    'User accounts for \\COMPUTERNAME',
    '',
    '-------------------------------------------------------------------------------',
    'Administrator          Guest                  User1                  User2',
    'The command completed successfully.'
])
def test_get_local_users_windows(mock_run_command, detector):
    detector.platform = "Windows"
    users = detector.get_local_users_windows()
    assert "Administrator" in users
    assert "User1" in users
    assert len(users) == 4

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
@patch.object(T1087AccountDiscovery, '_run_command', return_value=[
    'Group name     Domain Users',
    'Comment        Users who are part of the domain.',
    '',
    'Members',
    '',
    '-------------------------------------------------------------------------------',
    'DomainUser1            DomainUser2',
    'The command completed successfully.'
])
def test_get_domain_users_windows(mock_run_command, detector):
    detector.platform = "Windows"
    users = detector.get_domain_users_windows()
    assert "DomainUser1" in users
    assert "DomainUser2" in users
    assert len(users) == 2

@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test")
@patch.object(T1087AccountDiscovery, '_run_command', return_value=[
    'root:x:0:0:root:/root:/bin/bash',
    'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
    'user1:x:1000:1000:User One,,,:/home/user1:/bin/bash'
])
def test_get_users_unix_getent_success(mock_run_command, detector):
    detector.platform = "Linux" # or Darwin
    users_info = detector.get_users_unix()
    assert "user1" in users_info["local_users"]
    assert "root" in users_info["system_accounts"]
    assert len(users_info["local_users"]) == 1
    assert len(users_info["system_accounts"]) == 2

@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test")
@patch('src.discovery.account_discovery.open', new_callable=mock_open, read_data='\n'.join([
    'root:x:0:0:root:/root:/bin/bash',
    'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
    'user1:x:1000:1000:User One,,,:/home/user1:/bin/bash'
]))
@patch.object(T1087AccountDiscovery, '_run_command', return_value=[]) # Simulate getent failure
def test_get_users_unix_etc_passwd_fallback(mock_run_command, mock_open_file, detector):
    detector.platform = "Linux" # or Darwin
    users_info = detector.get_users_unix()
    assert "user1" in users_info["local_users"]
    assert "root" in users_info["system_accounts"]
    assert len(users_info["local_users"]) == 1
    assert len(users_info["system_accounts"]) == 2

@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test")
@patch.object(T1087AccountDiscovery, '_run_command', return_value=[]) # Simulate getent failure
@patch('src.discovery.account_discovery.open', side_effect=FileNotFoundError)
def test_get_users_unix_etc_passwd_not_found(mock_open_file, mock_run_command, detector):
    detector.platform = "Linux"
    users_info = detector.get_users_unix()
    assert users_info["local_users"] == []
    assert users_info["system_accounts"] == []

@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test")
@patch.object(T1087AccountDiscovery, '_run_command', return_value=[]) # Simulate getent failure
@patch('src.discovery.account_discovery.open', side_effect=PermissionError)
def test_get_users_unix_etc_passwd_permission_denied(mock_open_file, mock_run_command, detector):
    detector.platform = "Linux"
    users_info = detector.get_users_unix()
    assert users_info["local_users"] == []
    assert users_info["system_accounts"] == []

def test_run_checks_unsupported_platform(detector):
    detector.platform = "UnsupportedOS"
    results = detector.run_checks()
    assert results["status"] == "skipped"
    assert "Unsupported platform" in results["message"]

def test_run_checks_windows(detector):
    if platform.system() != "Windows":
        pytest.skip("Windows-specific test")
    with (
        patch.object(detector, 'get_local_users_windows', return_value=["Admin", "Guest"]),
        patch.object(detector, 'get_domain_users_windows', return_value=["DomainUser"])
    ):
        results = detector.run_checks()
        assert "Admin" in results["local_users"]
        assert "DomainUser" in results["domain_users"]
        assert results["status"] == "success"
        assert "execution_time" in results

def test_run_checks_unix(detector):
    if platform.system() == "Windows":
        pytest.skip("Unix-specific test")
    with patch.object(detector, 'get_users_unix', return_value={"local_users": ["user"], "system_accounts": ["root"]}):
        results = detector.run_checks()
        assert "user" in results["local_users"]
        assert "root" in results["system_accounts"]
        assert results["status"] == "success"
        assert "execution_time" in results

@patch('src.discovery.account_discovery.os.popen', side_effect=Exception("Test Error"))
def test_run_command_error_unix(mock_popen, detector):
    with patch('platform.system', return_value='Linux'):
        detector.platform = "Linux"
        result = detector._run_command("test command")
        assert result == []
        mock_popen.assert_called_once()

@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test")
@patch.object(T1087AccountDiscovery, '_run_command', return_value=[]) # Simulate getent failure
@patch('src.discovery.account_discovery.open', new_callable=mock_open, read_data='malformed:x:0:0:root:/root:/bin/bash')
def test_get_users_unix_etc_passwd_malformed(mock_open_file, mock_run_command, detector):
    detector.platform = "Linux"
    users_info = detector.get_users_unix()
    assert users_info["local_users"] == []
    assert users_info["system_accounts"] == ["malformed"] # The first part will still be extracted

@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test")
@patch.object(T1087AccountDiscovery, '_run_command', side_effect=Exception("Getent failed")) # Simulate getent failure
@patch('src.discovery.account_discovery.open', side_effect=Exception("Open failed")) # Simulate open failure
def test_get_users_unix_all_fail(mock_open_file, mock_run_command, detector):
    detector.platform = "Linux"
    users_info = detector.get_users_unix()
    assert users_info["local_users"] == []
    assert users_info["system_accounts"] == []

@patch('src.discovery.account_discovery.os.popen')
def test_run_command_success_unix(mock_popen, detector):
    mock_process = MagicMock()
    mock_process.read.return_value = "line1\nline2\n"
    mock_popen.return_value = mock_process
    
    with patch('platform.system', return_value='Linux'):
        detector.platform = "Linux"
        result = detector._run_command("test command")
        assert result == ["line1", "line2"]
        mock_popen.assert_called_once_with("test command")
        mock_process.close.assert_called_once()
