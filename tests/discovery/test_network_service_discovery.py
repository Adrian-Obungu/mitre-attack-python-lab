import unittest
from unittest.mock import patch, MagicMock
import json
import platform
import subprocess
from src.discovery.network_service_discovery import T1046NetworkServiceDiscovery

class TestT1046NetworkServiceDiscovery(unittest.TestCase):

    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('subprocess.run')
    def test_get_local_services_windows(self, mock_subprocess_run):
        """
        Tests _get_local_services_windows method with mock netstat -ano and tasklist output.
        """
        mock_subprocess_run.side_effect = [
            # Mock for netstat -ano
            MagicMock(
                stdout="""
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       908
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:49667        0.0.0.0:0              LISTENING       1234
  TCP    [::]:135               [::]:0                 LISTENING       908
  UDP    0.0.0.0:123            *:*                                    1000
  The command completed successfully.
""",
                stderr="",
                returncode=0
            ),
            # Mock for tasklist /svc /FI "PID eq 908" (for 0.0.0.0:135)
            MagicMock(
                stdout="""
Image Name                   PID Services
========================= ====== ============================================
svchost.exe                  908 RpcEptMapper, RpcSs
""",
                stderr="",
                returncode=0
            ),
            # Mock for tasklist /svc /FI "PID eq 4" (for 0.0.0.0:445)
            MagicMock(
                stdout="""
Image Name                   PID Services
========================= ====== ============================================
System                         4 N/A
""",
                stderr="",
                returncode=0
            ),
            # Mock for tasklist /svc /FI "PID eq 1234" (for 127.0.0.1:49667)
            MagicMock(
                stdout="""
Image Name                   PID Services
========================= ====== ============================================
python.exe                  1234 N/A
""",
                stderr="",
                returncode=0
            ),
            # Mock for tasklist /svc /FI "PID eq 908" (for [::]:135)
            MagicMock(
                stdout="""
Image Name                   PID Services
========================= ====== ============================================
svchost.exe                  908 RpcEptMapper, RpcSs
""",
                stderr="",
                returncode=0
            ),
            # Mock for tasklist /svc /FI "PID eq 1000" (for UDP 0.0.0.0:123)
            MagicMock(
                stdout="""
Image Name                   PID Services
========================= ====== ============================================
someprocess.exe               1000 N/A
""",
                stderr="",
                returncode=0
            )
        ]

        detector = T1046NetworkServiceDiscovery()
        local_services = detector._get_local_services_windows()

        expected_services = [
            {"protocol": "tcp", "local_address": "0.0.0.0:135", "state": "listening", "process": "svchost.exe"},
            {"protocol": "tcp", "local_address": "0.0.0.0:445", "state": "listening", "process": "System"},
            {"protocol": "tcp", "local_address": "127.0.0.1:49667", "state": "listening", "process": "python.exe"},
            {"protocol": "tcp", "local_address": "[::]:135", "state": "listening", "process": "svchost.exe"},
            {"protocol": "udp", "local_address": "0.0.0.0:123", "state": "", "process": "someprocess.exe"} # State is empty for UDP in netstat -ano output
        ]

        self.assertEqual(local_services, expected_services)
        self.assertEqual(mock_subprocess_run.call_count, 6) # 1 netstat + 5 tasklist calls
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "netstat", "-ano"],
            capture_output=True, text=True, timeout=detector.port_timeout * 5, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "tasklist", "/svc", "/FI", "PID eq 908"],
            capture_output=True, text=True, timeout=detector.port_timeout, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "tasklist", "/svc", "/FI", "PID eq 4"],
            capture_output=True, text=True, timeout=detector.port_timeout, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "tasklist", "/svc", "/FI", "PID eq 1234"],
            capture_output=True, text=True, timeout=detector.port_timeout, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "tasklist", "/svc", "/FI", "PID eq 1000"],
            capture_output=True, text=True, timeout=detector.port_timeout, check=False
        )


    @patch('platform.system', MagicMock(return_value="Linux"))
    @patch('subprocess.run')
    def test_get_local_services_linux(self, mock_subprocess_run):
        """
        Tests _get_local_services_linux method with mock ss -tulnp output.
        """
        mock_subprocess_run.return_value = MagicMock(
            stdout="""
Netid State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
udp   UNCONN     0      0            0.0.0.0:68                 0.0.0.0:*                    users:(("dhclient",pid=900,fd=6))
tcp   LISTEN     0      128        127.0.0.1:25                 0.0.0.0:*                    users:(("master",pid=1200,fd=13))
tcp   LISTEN     0      128          0.0.0.0:22               0.0.0.0:*                    users:(("sshd",pid=839,fd=3))
tcp   LISTEN     0      128        127.0.0.1:631                0.0.0.0:*                    users:(("cupsd",pid=850,fd=7))
tcp   LISTEN     0      128             [::]:80               [::]:*                     users:(("apache2",pid=1500,fd=4))
The command completed successfully.
""",
            stderr="",
            returncode=0
        )

        detector = T1046NetworkServiceDiscovery()
        local_services = detector._get_local_services_linux()

        expected_services = [
            {"protocol": "udp", "local_address": "0.0.0.0:68", "state": "unconn", "process": "dhclient"},
            {"protocol": "tcp", "local_address": "127.0.0.1:25", "state": "listen", "process": "master"},
            {"protocol": "tcp", "local_address": "0.0.0.0:22", "state": "listen", "process": "sshd"},
            {"protocol": "tcp", "local_address": "127.0.0.1:631", "state": "listen", "process": "cupsd"},
            {"protocol": "tcp", "local_address": "[::]:80", "state": "listen", "process": "apache2"}
        ]
        
        self.assertEqual(local_services, expected_services)
        mock_subprocess_run.assert_called_once_with(
            ["ss", "-tulnp"],
            capture_output=True, text=True, timeout=detector.port_timeout * 5, check=False
        )

    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('subprocess.run')
    def test_run_checks_windows(self, mock_subprocess_run):
        """
        Tests run_checks method on Windows.
        """
        mock_subprocess_run.side_effect = [
            # Mock for netstat -ano
            MagicMock(
                stdout="""
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       100
  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       200
  The command completed successfully.
""",
                stderr="",
                returncode=0
            ),
            # Mock for tasklist /svc /FI "PID eq 100"
            MagicMock(
                stdout="""
Image Name                   PID Services
========================= ====== ============================================
httpd.exe                    100 N/A
""",
                stderr="",
                returncode=0
            ),
            # Mock for tasklist /svc /FI "PID eq 200"
            MagicMock(
                stdout="""
Image Name                   PID Services
========================= ====== ============================================
tomcat.exe                   200 N/A
""",
                stderr="",
                returncode=0
            )
        ]

        detector = T1046NetworkServiceDiscovery()
        results = detector.run_checks()

        expected_local_services = [
            {"protocol": "tcp", "local_address": "0.0.0.0:80", "state": "listening", "process": "httpd.exe"},
            {"protocol": "tcp", "local_address": "127.0.0.1:8080", "state": "listening", "process": "tomcat.exe"}
        ]

        self.assertEqual(results["local_services"], expected_local_services)
        self.assertEqual(results["network_services"], [])
        self.assertEqual(results["vulnerable_services"], [])
        self.assertEqual(results["status"], "success")
        self.assertIn("execution_time", results)
        
        self.assertEqual(mock_subprocess_run.call_count, 3) # 1 netstat + 2 tasklist calls
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "netstat", "-ano"],
            capture_output=True, text=True, timeout=detector.port_timeout * 5, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "tasklist", "/svc", "/FI", "PID eq 100"],
            capture_output=True, text=True, timeout=detector.port_timeout, check=False
        )
        mock_subprocess_run.assert_any_call(
            ["powershell.exe", "-Command", "tasklist", "/svc", "/FI", "PID eq 200"],
            capture_output=True, text=True, timeout=detector.port_timeout, check=False
        )

    @patch('platform.system', MagicMock(return_value="Linux"))
    @patch('subprocess.run')
    def test_run_checks_linux(self, mock_subprocess_run):
        """
        Tests run_checks method on Linux.
        """
        mock_subprocess_run.return_value = MagicMock(
            stdout="""
Netid State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
udp   UNCONN     0      0            0.0.0.0:53                 0.0.0.0:*                    users:(("dnsmasq",pid=1000,fd=7))
tcp   LISTEN     0      128          0.0.0.0:22               0.0.0.0:*                    users:(("sshd",pid=800,fd=3))
The command completed successfully.
""",
            stderr="",
            returncode=0
        )

        detector = T1046NetworkServiceDiscovery()
        results = detector.run_checks()

        expected_local_services = [
            {"protocol": "udp", "local_address": "0.0.0.0:53", "state": "unconn", "process": "dnsmasq"},
            {"protocol": "tcp", "local_address": "0.0.0.0:22", "state": "listen", "process": "sshd"}
        ]
        
        self.assertEqual(results["local_services"], expected_local_services)
        self.assertEqual(results["network_services"], [])
        self.assertEqual(results["vulnerable_services"], [])
        self.assertEqual(results["status"], "success")
        self.assertIn("execution_time", results)

        mock_subprocess_run.assert_called_once_with(
            ["ss", "-tulnp"],
            capture_output=True, text=True, timeout=detector.port_timeout * 5, check=False
        )

    @patch('platform.system', MagicMock(return_value="Solaris"))
    def test_run_checks_unsupported_platform(self):
        """
        Tests run_checks method on an unsupported platform.
        """
        detector = T1046NetworkServiceDiscovery()
        results = detector.run_checks()

        self.assertEqual(results["status"], "skipped")
        self.assertIn("Unsupported platform: Solaris", results["message"])
        self.assertEqual(results["local_services"], [])
        self.assertEqual(results["network_services"], [])
        self.assertEqual(results["vulnerable_services"], [])

    @patch('platform.system', MagicMock(return_value="Windows"))
    @patch('subprocess.run')
    def test_timeout_get_local_services_windows(self, mock_subprocess_run):
        """
        Tests timeout handling for _get_local_services_windows.
        """
        mock_subprocess_run.side_effect = subprocess.TimeoutExpired(cmd=["netstat", "-ano"], timeout=10)

        detector = T1046NetworkServiceDiscovery()
        local_services = detector._get_local_services_windows()

        self.assertEqual(local_services, [])
        mock_subprocess_run.assert_called_once_with(
            ["powershell.exe", "-Command", "netstat", "-ano"],
            capture_output=True, text=True, timeout=detector.port_timeout * 5, check=False
        )
    
    @patch('platform.system', MagicMock(return_value="Linux"))
    @patch('subprocess.run')
    def test_timeout_get_local_services_linux(self, mock_subprocess_run):
        """
        Tests timeout handling for _get_local_services_linux.
        """
        mock_subprocess_run.side_effect = subprocess.TimeoutExpired(cmd=["ss", "-tulnp"], timeout=10)

        detector = T1046NetworkServiceDiscovery()
        local_services = detector._get_local_services_linux()

        self.assertEqual(local_services, [])
        mock_subprocess_run.assert_called_once_with(
            ["ss", "-tulnp"],
            capture_output=True, text=True, timeout=detector.port_timeout * 5, check=False
        )

if __name__ == '__main__':
    unittest.main()