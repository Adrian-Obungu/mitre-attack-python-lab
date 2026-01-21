import unittest
from unittest.mock import patch, MagicMock
import json
import platform
import ipaddress
import logging
from src.discovery.network_share_discovery import T1135NetworkShareDiscovery

class TestT1135NetworkShareDiscovery(unittest.TestCase):

    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('subprocess.run')
    def test_get_local_shares_windows(self, mock_subprocess_run):
        """
        Tests the _get_local_shares_windows method with mock net share output.
        """
        mock_output = """
        Share name   Resource                        Description
        
        -------------------------------------------------------------------------------
        ADMIN$       C:\\Windows                      Remote Admin
        C$           C:\\                            Default share
        IPC$                                         Remote IPC
        ShareFolder  C:\\Users\\User\\ShareFolder    My Shared Folder
        The command completed successfully.
        """
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_output,
            stderr="",
            returncode=0
        )

        detector = T1135NetworkShareDiscovery()
        local_shares = detector._get_local_shares_windows()

        expected_shares = [
            {"name": "ADMIN$", "path": "C:\\Windows", "type": "administrative"},
            {"name": "C$", "path": "C:\\", "type": "administrative"},
            {"name": "IPC$", "path": "N/A", "type": "IPC"},
            {"name": "ShareFolder", "path": "C:\\Users\\User\\ShareFolder", "type": "disk"}
        ]
        
        self.assertEqual(len(local_shares), len(expected_shares))
        for i, share in enumerate(local_shares):
            self.assertIn(share, expected_shares)
        mock_subprocess_run.assert_called_once_with(
            ["net", "share"],
            capture_output=True,
            text=True,
            timeout=None,
            check=False
        )

    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('subprocess.run')
    def test_get_network_shares_windows_localhost(self, mock_subprocess_run):
        """
        Tests the _get_network_shares_windows method for localhost with mock net view output.
        """
        mock_output = """
        Server Name            \\\\LOCALHOST
        
        Share name   Type      Used as  Comment
        -------------------------------------------------------------------------------
        ADMIN$       Disk               Remote Admin
        C$           Disk               Default share
        IPC$         IPC                Remote IPC
        NETLOGON     Disk               Logon server share 
        SYSVOL       Disk               Logon server share 
        Users        Disk               User Profiles
        The command completed successfully.
        """
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_output,
            stderr="",
            returncode=0
        )

        detector = T1135NetworkShareDiscovery()
        network_shares = detector._get_network_shares_windows("127.0.0.1")

        expected_shares = [
            {"host": "127.0.0.1", "share": "ADMIN$", "accessible": True},
            {"host": "127.0.0.1", "share": "C$", "accessible": True},
            {"host": "127.0.0.1", "share": "IPC$", "accessible": True},
            {"host": "127.0.0.1", "share": "NETLOGON", "accessible": True},
            {"host": "127.0.0.1", "share": "SYSVOL", "accessible": True},
            {"host": "127.0.0.1", "share": "Users", "accessible": True}
        ]

        self.assertEqual(network_shares, expected_shares)
        mock_subprocess_run.assert_called_once_with(
            ["net", "view", "\\\\127.0.0.1"],
            capture_output=True,
            text=True,
            timeout=detector.network_timeout,
            check=False
        )

    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('subprocess.run')
    def test_run_checks_windows(self, mock_subprocess_run):
        """
        Tests the run_checks method on Windows, mocking both net share and net view.
        """
        mock_subprocess_run.side_effect = [
            # Mock for net share
            MagicMock(
                stdout="""
Share name   Resource                        Description
-------------------------------------------------------------------------------
ADMIN$       C:\\Windows                      Remote Admin
ShareFolder  C:\\Users\\User\\ShareFolder    My Shared Folder
The command completed successfully.
""",
                stderr="",
                returncode=0
            ),
            # Mock for net view \\127.0.0.1
            MagicMock(
                stdout="""
Server Name            \\\\LOCALHOST
Share name   Type      Used as  Comment
-------------------------------------------------------------------------------
IPC$         IPC                Remote IPC
Users        Disk               User Profiles
The command completed successfully.
""",
                stderr="",
                returncode=0
            )
        ]

        detector = T1135NetworkShareDiscovery()
        results = detector.run_checks()

        expected_local_shares = [
            {"name": "ADMIN$", "path": "C:\\Windows", "type": "administrative"},
            {"name": "ShareFolder", "path": "C:\\Users\\User\\ShareFolder", "type": "disk"}
        ]
        expected_network_shares = [
            {"host": "127.0.0.1", "share": "IPC$", "accessible": True},
            {"host": "127.0.0.1", "share": "Users", "accessible": True}
        ]

        self.assertEqual(results["local_shares"], expected_local_shares)
        self.assertEqual(results["network_shares"], expected_network_shares)
        self.assertEqual(results["status"], "success")
        self.assertEqual(results["scan_range"], "localhost")
        
        # Ensure subprocess.run was called twice with correct arguments
        mock_subprocess_run.assert_any_call(
            ["net", "share"],
            capture_output=True,
            text=True,
            timeout=None,
            check=False
        )
        mock_subprocess_run.assert_any_call(
            ["net", "view", "\\\\127.0.0.1"],
            capture_output=True,
            text=True,
            timeout=detector.network_timeout,
            check=False
        )

    @patch('platform.system', MagicMock(return_value="Linux"))
    @patch('subprocess.run')
    def test_get_local_shares_unix(self, mock_subprocess_run):
        """
        Tests the _get_local_shares_unix method.
        """
        # Since it's a placeholder, it should return an empty list.
        detector = T1135NetworkShareDiscovery()
        local_shares = detector._get_local_shares_unix()
        self.assertEqual(local_shares, [])
        # Ensure no subprocess commands were run
        mock_subprocess_run.assert_not_called()

    @patch('platform.system', MagicMock(return_value="Linux"))
    @patch('subprocess.run')
    def test_get_network_shares_unix_localhost(self, mock_subprocess_run):
        """
        Tests the _get_network_shares_unix method for localhost with mock smbclient -L output.
        """
        mock_output = """
        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba 4.x)
        SharedDocs      Disk      User Shared Documents
        homes           Disk      Home Directories
        The command completed successfully.
        """
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_output,
            stderr="",
            returncode=0
        )

        detector = T1135NetworkShareDiscovery()
        network_shares = detector._get_network_shares_unix("127.0.0.1")

        expected_shares = [
            {"host": "127.0.0.1", "share": "IPC$", "accessible": True},
            {"host": "127.0.0.1", "share": "SharedDocs", "accessible": True},
            {"host": "127.0.0.1", "share": "homes", "accessible": True}
        ]

        self.assertEqual(network_shares, expected_shares)
        mock_subprocess_run.assert_called_once_with(
            ["smbclient", "-L", "//127.0.0.1", "-N"],
            capture_output=True,
            text=True,
            timeout=detector.network_timeout,
            check=False
        )

    @patch('platform.system', MagicMock(return_value="Linux"))
    @patch('subprocess.run')
    def test_run_checks_linux(self, mock_subprocess_run):
        """
        Tests the run_checks method on Linux, mocking smbclient -L.
        """
        mock_subprocess_run.side_effect = [
            # Mock for smbclient -L //127.0.0.1 -N
            MagicMock(
                stdout="""
Sharename       Type      Comment
---------       ----      -------
IPC$            IPC       IPC Service (Samba 4.x)
SharedDocs      Disk      User Shared Documents
The command completed successfully.
""",
                stderr="",
                returncode=0
            )
        ]

        detector = T1135NetworkShareDiscovery()
        results = detector.run_checks()

        expected_local_shares = [] # As currently implemented
        expected_network_shares = [
            {"host": "127.0.0.1", "share": "IPC$", "accessible": True},
            {"host": "127.0.0.1", "share": "SharedDocs", "accessible": True}
        ]

        self.assertEqual(results["local_shares"], expected_local_shares)
        self.assertEqual(results["network_shares"], expected_network_shares)
        self.assertEqual(results["status"], "success")
        self.assertEqual(results["scan_range"], "localhost")

        mock_subprocess_run.assert_called_once_with(
            ["smbclient", "-L", "//127.0.0.1", "-N"],
            capture_output=True,
            text=True,
            timeout=detector.network_timeout,
            check=False
        )

    @patch('platform.system')
    @patch('subprocess.run')
    def test_scan_network_range_windows(self, mock_subprocess_run, mock_platform_system):
        mock_platform_system.return_value = "Windows"

        # Explicitly setting up side_effect for the calls to _get_network_shares_windows for specific IPs
        # This will be tricky because the order of host processing in ThreadPoolExecutor is not guaranteed.
        # Instead of `side_effect` on `mock_subprocess_run` directly, which relies on call order,
        # we can mock the `_get_network_shares_windows` and `_get_network_shares_unix` methods directly.
        
        detector = T1135NetworkShareDiscovery(max_concurrent_hosts=2)
        cidr_range = "192.168.1.0/29" # Includes .0 to .7, total 8 hosts

        with patch.object(detector, '_get_network_shares_windows') as mock_get_network_shares_windows:
            # Mock the behavior of _get_network_shares_windows for different hosts
            def mock_get_shares_for_host(host):
                if host == "192.168.1.1":
                    return [{"host": "192.168.1.1", "share": "SHARE1", "accessible": True}]
                elif host == "192.168.1.2":
                    return [{"host": "192.168.1.2", "share": "SHARE2", "accessible": True}]
                elif host == "127.0.0.1":
                    return [{"host": "127.0.0.1", "share": "LOCALHOST_SHARE", "accessible": True}]
                else:
                    return [] # No shares for other hosts or unreachable

            mock_get_network_shares_windows.side_effect = mock_get_shares_for_host
            
            discovered_shares = detector._scan_network_range(cidr_range)

            expected_shares = [
                {"host": "127.0.0.1", "share": "LOCALHOST_SHARE", "accessible": True},
                {"host": "192.168.1.1", "share": "SHARE1", "accessible": True},
                {"host": "192.168.1.2", "share": "SHARE2", "accessible": True}
            ]

            # We need to sort both lists to compare them because order is not guaranteed.
            self.assertCountEqual(discovered_shares, expected_shares)
            
            # Assert that _get_network_shares_windows was called for each host in the CIDR range plus localhost.
            # ipaddress.ip_network("192.168.1.0/29") includes 8 hosts (192.168.1.0 - 192.168.1.7).
            # Plus localhost, so 9 calls in total.
            self.assertEqual(mock_get_network_shares_windows.call_count, len(list(ipaddress.ip_network(cidr_range).hosts())) + 1)
    
    @patch('platform.system')
    @patch('subprocess.run')
    def test_scan_network_range_linux(self, mock_subprocess_run, mock_platform_system):
        mock_platform_system.return_value = "Linux"

        detector = T1135NetworkShareDiscovery(max_concurrent_hosts=2)
        cidr_range = "192.168.1.0/29" 

        # Explicitly setting up side_effect for the calls to _get_network_shares_unix for specific IPs
        with patch.object(detector, '_get_network_shares_unix') as mock_get_network_shares_unix:
            def mock_get_shares_for_host_unix(host):
                if host == "192.168.1.1":
                    return [{"host": "192.168.1.1", "share": "UNIX_SHARE1", "accessible": True}]
                elif host == "192.168.1.2":
                    return [{"host": "192.168.1.2", "share": "UNIX_SHARE2", "accessible": True}]
                elif host == "127.0.0.1":
                    return [{"host": "127.0.0.1", "share": "UNIX_LOCALHOST_SHARE", "accessible": True}]
                else:
                    return []

            mock_get_network_shares_unix.side_effect = mock_get_shares_for_host_unix
            
            discovered_shares = detector._scan_network_range(cidr_range)

            expected_shares = [
                {"host": "127.0.0.1", "share": "UNIX_LOCALHOST_SHARE", "accessible": True},
                {"host": "192.168.1.1", "share": "UNIX_SHARE1", "accessible": True},
                {"host": "192.168.1.2", "share": "UNIX_SHARE2", "accessible": True}
            ]
            self.assertCountEqual(discovered_shares, expected_shares)
            self.assertEqual(mock_get_network_shares_unix.call_count, len(list(ipaddress.ip_network(cidr_range).hosts())) + 1)

    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('subprocess.run')
    def test_run_checks_windows_with_scan_range(self, mock_subprocess_run):
        """
        Tests the run_checks method on Windows with a scan_range.
        """
        mock_subprocess_run.side_effect = [
            # Mock for net share (local shares)
            MagicMock(
                stdout="""
Share name   Resource                        Description
-------------------------------------------------------------------------------
ADMIN$       C:\\Windows                      Remote Admin
The command completed successfully.
""",
                stderr="",
                returncode=0
            )
        ]

        # Mock the _scan_network_range method directly to control its output
        with patch('src.discovery.network_share_discovery.T1135NetworkShareDiscovery._scan_network_range') as mock_scan_network_range:
            mock_scan_network_range.return_value = [
                {"host": "192.168.1.1", "share": "NET_SHARE_WIN", "accessible": True}
            ]
            detector = T1135NetworkShareDiscovery()
            cidr_range = "192.168.1.0/30"
            results = detector.run_checks(scan_range=cidr_range)

            expected_local_shares = [
                {"name": "ADMIN$", "path": "C:\\Windows", "type": "administrative"}
            ]
            expected_network_shares = [
                {"host": "192.168.1.1", "share": "NET_SHARE_WIN", "accessible": True}
            ]

            self.assertEqual(results["local_shares"], expected_local_shares)
            self.assertEqual(results["network_shares"], expected_network_shares)
            self.assertEqual(results["status"], "success")
            self.assertEqual(results["scan_range"], cidr_range)
            mock_scan_network_range.assert_called_once_with(cidr_range)

    @patch('platform.system', MagicMock(return_value="Linux"))
    @patch('subprocess.run')
    def test_run_checks_linux_with_scan_range(self, mock_subprocess_run):
        """
        Tests the run_checks method on Linux with a scan_range.
        """
        # Mock the _scan_network_range method directly to control its output
        with patch('src.discovery.network_share_discovery.T1135NetworkShareDiscovery._scan_network_range') as mock_scan_network_range:
            mock_scan_network_range.return_value = [
                {"host": "192.168.1.1", "share": "NET_SHARE_LINUX", "accessible": True}
            ]
            detector = T1135NetworkShareDiscovery()
            cidr_range = "192.168.1.0/30"
            results = detector.run_checks(scan_range=cidr_range)

            expected_local_shares = [] # _get_local_shares_unix is a placeholder
            expected_network_shares = [
                {"host": "192.168.1.1", "share": "NET_SHARE_LINUX", "accessible": True}
            ]

            self.assertEqual(results["local_shares"], expected_local_shares)
            self.assertEqual(results["network_shares"], expected_network_shares)
            self.assertEqual(results["status"], "success")
            self.assertEqual(results["scan_range"], cidr_range)
            mock_scan_network_range.assert_called_once_with(cidr_range)

    @patch('logging.Logger.warning')
    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('subprocess.run')
    def test_logging_sensitive_local_shares_windows(self, mock_subprocess_run, mock_logger_warning):
        """
        Tests that appropriate warnings are logged for sensitive local shares on Windows.
        """
        mock_output = """
        Share name   Resource                        Description
        
        -------------------------------------------------------------------------------
        ADMIN$       C:\\Windows                      Remote Admin
        HR_DATA      C:\\Sensitive\\HR_Data           Human Resources Data
        Secret$      C:\\SecretFolder                 Hidden secret
        IPC$                                         Remote IPC
        The command completed successfully.
        """
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_output,
            stderr="",
            returncode=0
        )

        detector = T1135NetworkShareDiscovery()
        detector._get_local_shares_windows()

        mock_logger_warning.assert_any_call(
            "Windows: Administrative share 'ADMIN$' detected locally. This can be a target for attackers."
        )
        mock_logger_warning.assert_any_call(
            "Windows: Potentially sensitive local share 'HR_DATA' at 'C:\\Sensitive\\HR_Data' detected due to keyword 'HR'."
        )
        mock_logger_warning.assert_any_call(
            "Windows: Administrative share 'Secret$' detected locally. This can be a target for attackers."
        )
        self.assertEqual(mock_logger_warning.call_count, 3)

    @patch('logging.Logger.warning')
    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('subprocess.run')
    def test_logging_sensitive_network_shares_windows(self, mock_subprocess_run, mock_logger_warning):
        """
        Tests that appropriate warnings are logged for sensitive network shares on Windows.
        """
        mock_output = """
        Server Name            \\\\REMOTEHOST
        
        Share name   Type      Used as  Comment
        -------------------------------------------------------------------------------
        ADMIN$       Disk               Remote Admin
        FINANCE_DOCS Disk               Financial Documents
        C$           Disk               Default share
        IPC$         IPC                Remote IPC
        The command completed successfully.
        """
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_output,
            stderr="",
            returncode=0
        )

        detector = T1135NetworkShareDiscovery()
        detector._get_network_shares_windows("REMOTEHOST")

        mock_logger_warning.assert_any_call(
            "Windows: Administrative share 'ADMIN$' detected on host 'REMOTEHOST'. This can be a target for attackers."
        )
        mock_logger_warning.assert_any_call(
            "Windows: Potentially sensitive network share 'FINANCE_DOCS' on host 'REMOTEHOST' detected due to keyword 'FINANCE'."
        )
        mock_logger_warning.assert_any_call(
            "Windows: Administrative share 'C$' detected on host 'REMOTEHOST'. This can be a target for attackers."
        )
        self.assertEqual(mock_logger_warning.call_count, 3)

    @patch('logging.Logger.warning')
    @patch('platform.system', MagicMock(return_value="Linux"))
    @patch('subprocess.run')
    def test_logging_sensitive_network_shares_unix(self, mock_subprocess_run, mock_logger_warning):
        """
        Tests that appropriate warnings are logged for sensitive network shares on Unix-like systems.
        """
        mock_output = """
        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba 4.x)
        DATA_SHARE      Disk      Important Data
        root$           Disk      Admin share for root
        The command completed successfully.
        """
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_output,
            stderr="",
            returncode=0
        )

        detector = T1135NetworkShareDiscovery()
        detector._get_network_shares_unix("192.168.1.100")

        mock_logger_warning.assert_any_call(
            "Unix: Administrative share 'root$' detected on host '192.168.1.100'. This can be a target for attackers."
        )
        mock_logger_warning.assert_any_call(
            "Unix: Potentially sensitive network share 'DATA_SHARE' on host '192.168.1.100' detected due to keyword 'DATA'."
        )
        self.assertEqual(mock_logger_warning.call_count, 2)


if __name__ == '__main__':
    unittest.main()
