import unittest
from unittest.mock import patch, MagicMock
import json
import platform
import os
import time # For checking execution time in run_checks mock
import subprocess # Import subprocess
from src.discovery.permission_groups_discovery import T1069PermissionGroupsDiscovery

class TestT1069PermissionGroupsDiscovery(unittest.TestCase):

    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('subprocess.run')
    def test_get_local_groups_windows(self, mock_subprocess_run):
        """
        Tests _get_local_groups_windows method with mock net localgroup output.
        """
        mock_subprocess_run.side_effect = [
            # First call: net localgroup (to get all group names)
            MagicMock(
                stdout=r"""
Aliases for \\COMPUTERNAME

-------------------------------------------------------------------------------
*Administrators
*Guests
*Users
The command completed successfully.
""",
                stderr="",
                returncode=0
            ),
            # Second call: net localgroup Administrators
            MagicMock(
                stdout=r"""
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
User1
User2
The command completed successfully.
""",
                stderr="",
                returncode=0
            ),
            # Third call: net localgroup Guests
            MagicMock(
                stdout=r"""
Alias name     Guests
Comment        Guests have limited access to computer/domain guests
Members
-------------------------------------------------------------------------------
GuestUser
The command completed successfully.
""",
                stderr="",
                returncode=0
            ),
            # Fourth call: net localgroup Users
            MagicMock(
                stdout=r"""
Alias name     Users
Comment        Users are prevented from making accidental or intentional system-wide changes.
Members
-------------------------------------------------------------------------------
User3
User4
The command completed successfully.
""",
                stderr="",
                returncode=0
            )
        ]
        
        detector = T1069PermissionGroupsDiscovery()
        local_groups = detector._get_local_groups_windows()

        expected_groups = [
            {"name": "Administrators", "description": "Administrators have complete and unrestricted access to the computer/domain", "members": ["User1", "User2"]},
            {"name": "Guests", "description": "Guests have limited access to computer/domain guests", "members": ["GuestUser"]},
            {"name": "Users", "description": "Users are prevented from making accidental or intentional system-wide changes.", "members": ["User3", "User4"]}
        ]

        # Sort both lists by group name for reliable comparison
        local_groups_sorted = sorted(local_groups, key=lambda x: x['name'])
        expected_groups_sorted = sorted(expected_groups, key=lambda x: x['name'])

        self.assertEqual(local_groups_sorted, expected_groups_sorted)
        self.assertEqual(mock_subprocess_run.call_count, 4)
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "net", "localgroup"], 
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "net", "localgroup", "Administrators"], 
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "net", "localgroup", "Guests"], 
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "net", "localgroup", "Users"], 
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )

    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('os.getlogin', MagicMock(return_value="testuser"))
    @patch('subprocess.run')
    def test_get_current_user_groups_windows(self, mock_subprocess_run):
        """
        Tests _get_current_user_groups_windows method with mock whoami /groups output.
        """
        mock_output = r"""
        INFO: A list of the user's group memberships follows.

        Group Name                             Type             SID          Attributes                                      
        ====================================== ================ ============ ===============================================
        Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default             
        BUILTIN\Administrators                 Alias            S-1-5-32-544 Group used for administrative access to the computer/domain
        BUILTIN\Users                         Alias            S-1-5-32-545 Mandatory group, Enabled by default             
        NT AUTHORITY\AUTHENTICATED USERS      Well-known group S-1-5-11     Mandatory group, Enabled by default             
        NT AUTHORITY\This Organization        Well-known group S-1-5-15     Mandatory group, Enabled by default             
        LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default             
        The command completed successfully.
        """
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_output,
            stderr="",
            returncode=0
        )

        detector = T1069PermissionGroupsDiscovery()
        user_memberships = detector._get_current_user_groups_windows()

        expected_memberships = {
            "testuser": [
                "Everyone", 
                r"BUILTIN\Administrators", 
                r"BUILTIN\Users", 
                r"NT AUTHORITY\AUTHENTICATED USERS", 
                r"NT AUTHORITY\This Organization", 
                "LOCAL"
            ]
        }
        self.assertEqual(user_memberships, expected_memberships)
        mock_subprocess_run.assert_called_once_with(
            ["powershell.exe", "-Command", "whoami", "/groups"],
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )

    @patch('platform.system', MagicMock(return_value="Linux"))
    @patch('os.getlogin', MagicMock(return_value="testuser"))
    @patch('subprocess.run')
    def test_get_local_groups_unix(self, mock_subprocess_run):
        """
        Tests _get_local_groups_unix method with mock getent group output.
        """
        mock_output = """
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
    adm:x:4:syslog,testuser
wheel:x:10:testuser
sudo:x:27:testuser
users:x:100:
testgroup:x:1001:user1,user2
"""
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_output,
            stderr="",
            returncode=0
        )

        detector = T1069PermissionGroupsDiscovery()
        local_groups = detector._get_local_groups_unix()

        expected_groups = [
            {'name': 'root', 'gid': '0', 'members': []},
            {'name': 'daemon', 'gid': '1', 'members': []},
            {'name': 'bin', 'gid': '2', 'members': []},
            {'name': 'sys', 'gid': '3', 'members': []},
            {'name': 'adm', 'gid': '4', 'members': ['syslog', 'testuser']},
            {'name': 'wheel', 'gid': '10', 'members': ['testuser']},
            {'name': 'sudo', 'gid': '27', 'members': ['testuser']},
            {'name': 'users', 'gid': '100', 'members': []},
            {'name': 'testgroup', 'gid': '1001', 'members': ['user1', 'user2']}
        ]
        self.assertEqual(local_groups, expected_groups)
        mock_subprocess_run.assert_called_once_with(
            ["getent", "group"],
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )

    @patch('platform.system', MagicMock(return_value="Linux"))
    @patch('os.getlogin', MagicMock(return_value="testuser"))
    @patch('subprocess.run')
    def test_get_current_user_groups_unix(self, mock_subprocess_run):
        """
        Tests _get_current_user_groups_unix method with mock id -Gn output.
        """
        mock_output = "testuser adm wheel sudo docker"
        mock_subprocess_run.side_effect = [
            MagicMock(stdout=mock_output, stderr="", returncode=0) # For id -Gn
        ]

        detector = T1069PermissionGroupsDiscovery()
        user_memberships = detector._get_current_user_groups_unix()

        expected_memberships = {
            "testuser": ["testuser", "adm", "wheel", "sudo", "docker"]
        }
        self.assertEqual(user_memberships, expected_memberships)
        mock_subprocess_run.assert_called_once_with(
            ["id", "-Gn"],
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )

    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('os.getlogin', MagicMock(return_value="adminuser"))
    @patch('subprocess.run')
    def test_run_checks_windows(self, mock_subprocess_run):
        """
        Tests the run_checks method on Windows.
        """
        mock_subprocess_run.side_effect = [
            # First call: net localgroup (to get all group names)
            MagicMock(
                stdout=r"""
Aliases for \\COMPUTERNAME

-------------------------------------------------------------------------------
*Administrators
*Users
The command completed successfully.
""",
                stderr="",
                returncode=0
            ),
            # Second call: net localgroup Administrators
            MagicMock(
                stdout=r"""
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
adminuser
UserA
The command completed successfully.
""",
                stderr="",
                returncode=0
            ),
            # Third call: net localgroup Users
            MagicMock(
                stdout=r"""
Alias name     Users
Comment        Users are prevented from making accidental or intentional system-wide changes.
Members
-------------------------------------------------------------------------------
UserB
The command completed successfully.
""",
                stderr="",
                returncode=0
            ),
            # Fourth call: whoami /groups
            MagicMock(
                stdout=r"""
INFO: A list of the user's group memberships follows.

Group Name                             Type             SID          Attributes                                      
====================================== ================ ============ ===============================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default             
BUILTIN\Administrators                 Alias            S-1-5-32-544 Group used for administrative access to the computer/domain
BUILTIN\Users                         Alias            S-1-5-32-545 Mandatory group, Enabled by default             
The command completed successfully.
""",
                stderr="",
                returncode=0
            )
        ]

        detector = T1069PermissionGroupsDiscovery()
        results = detector.run_checks()

        expected_local_groups = [
            {"name": "Administrators", "description": "Administrators have complete and unrestricted access to the computer/domain", "members": ["adminuser", "UserA"]},
            {"name": "Users", "description": "Users are prevented from making accidental or intentional system-wide changes.", "members": ["UserB"]}  
        ]
        # Sorting for comparison
        expected_local_groups_sorted = sorted(expected_local_groups, key=lambda x: x['name'])
        results_local_groups_sorted = sorted(results["local_groups"], key=lambda x: x['name'])
        self.assertEqual(results_local_groups_sorted, expected_local_groups_sorted)

        expected_user_memberships = {
            "adminuser": [
                "Everyone", 
                r"BUILTIN\Administrators", 
                r"BUILTIN\Users"
            ]
        }
        self.assertEqual(results["user_memberships"], expected_user_memberships)
        
        expected_privileged_groups = ["Administrators", r"BUILTIN\Administrators"]
        self.assertCountEqual(results["privileged_groups"], expected_privileged_groups)
        
        self.assertEqual(results["status"], "success")
        self.assertIn("execution_time", results)

        self.assertEqual(mock_subprocess_run.call_count, 4)
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "net", "localgroup"], 
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "net", "localgroup", "Administrators"], 
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "net", "localgroup", "Users"], 
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "whoami", "/groups"], 
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )

    @patch('platform.system', MagicMock(return_value="Linux"))
    @patch('os.getlogin', MagicMock(return_value="linuxuser"))
    @patch('subprocess.run')
    def test_run_checks_linux(self, mock_subprocess_run):
        """
        Tests the run_checks method on Linux.
        """
        mock_subprocess_run.side_effect = [
            # First call: getent group
            MagicMock(
                stdout="""
root:x:0:
sudo:x:27:linuxuser,anotheruser
wheel:x:10:linuxuser
users:x:100:
""",
                stderr="",
                returncode=0
            ),
            # Second call: id -Gn
            MagicMock(
                stdout="linuxuser sudo wheel users",
                stderr="",
                returncode=0
            )
        ]

        detector = T1069PermissionGroupsDiscovery()
        results = detector.run_checks()

        expected_local_groups = [
            {'name': 'root', 'gid': '0', 'members': []},
            {'name': 'sudo', 'gid': '27', 'members': ['linuxuser', 'anotheruser']},
            {'name': 'wheel', 'gid': '10', 'members': ['linuxuser']},
            {'name': 'users', 'gid': '100', 'members': []}
        ]
        # Sorting for comparison
        expected_local_groups_sorted = sorted(expected_local_groups, key=lambda x: x['name'])
        results_local_groups_sorted = sorted(results["local_groups"], key=lambda x: x['name'])
        self.assertEqual(results_local_groups_sorted, expected_local_groups_sorted)

        expected_user_memberships = {
            "linuxuser": ["linuxuser", "sudo", "wheel", "users"]
        }
        self.assertEqual(results["user_memberships"], expected_user_memberships)

        expected_privileged_groups = ["root", "sudo", "wheel"] # Added "root" here
        self.assertCountEqual(results["privileged_groups"], expected_privileged_groups)

        self.assertEqual(results["status"], "success")
        self.assertIn("execution_time", results)

        self.assertEqual(mock_subprocess_run.call_count, 2)
        mock_subprocess_run.assert_any_call(
            ["getent", "group"], 
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["id", "-Gn"], 
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )


    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('os.getlogin', MagicMock(return_value="testuser"))
    @patch('subprocess.run')
    def test_caching_mechanism(self, mock_subprocess_run):
        """
        Tests that results are cached and subsequent calls return from cache.
        """
        mock_subprocess_run.side_effect = [
            # First call: net localgroup
            MagicMock(
                stdout=r"""
Aliases for \\COMPUTERNAME
-------------------------------------------------------------------------------
*Administrators
The command completed successfully.
""",
                stderr="",
                returncode=0
            ),
            # Second call: net localgroup Administrators
            MagicMock(
                stdout=r"""
Alias name     Administrators
Members
-------------------------------------------------------------------------------
testuser
The command completed successfully.
""",
                stderr="",
                returncode=0
            ),
            # Third call: whoami /groups
            MagicMock(
                stdout=r"""
Group Name                             Type             SID          Attributes                                      
====================================== ================ ============ ===============================================
BUILTIN\Administrators                 Alias            S-1-5-32-544 Group used for administrative access to the computer/domain
The command completed successfully.
""",
                stderr="",
                returncode=0
            )
        ]

        detector = T1069PermissionGroupsDiscovery()
        # First run, should execute commands
        first_results = detector.run_checks()
        # The number of calls is 3 (1 for net localgroup, 1 for net localgroup Administrators, 1 for whoami /groups)
        self.assertEqual(mock_subprocess_run.call_count, 3)

        # Second run, should return from cache
        second_results = detector.run_checks()
        self.assertEqual(mock_subprocess_run.call_count, 3) # Should not have called any new commands
        self.assertEqual(first_results, second_results)
        
        expected_privileged_groups = ["Administrators", r"BUILTIN\Administrators"]
        self.assertCountEqual(first_results["privileged_groups"], expected_privileged_groups)

    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('subprocess.run')
    def test_timeout_handling(self, mock_subprocess_run):
        """
        Tests that command timeouts are handled gracefully.
        """
        mock_subprocess_run.side_effect = [
            subprocess.TimeoutExpired(cmd=["net", "localgroup"], timeout=10),
            subprocess.TimeoutExpired(cmd=["whoami", "/groups"], timeout=10)
        ]

        detector = T1069PermissionGroupsDiscovery(enumeration_timeout=1)
        results = detector.run_checks() 
        
        self.assertEqual(results["status"], "success") # Still success, but local_groups would be empty
        self.assertEqual(results["local_groups"], [])
        self.assertEqual(results["privileged_groups"], [])
        self.assertEqual(mock_subprocess_run.call_count, 2) # Both net localgroup and whoami /groups attempt
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "net", "localgroup"], 
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "whoami", "/groups"], 
            capture_output=True, text=True, timeout=detector.enumeration_timeout, check=False
        )

if __name__ == '__main__':
    unittest.main()