# -*- coding: utf-8 -*-
"""
Tests for src.lateral_movement
Covers: T1550AlternateAuthDetector, T1021RemoteServicesDetector,
        and T1078ValidAccountsDetector.
"""
import unittest
import platform
import stat
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

from src.lateral_movement.alternate_auth import T1550AlternateAuthDetector
from src.lateral_movement.remote_services import T1021RemoteServicesDetector
from src.lateral_movement.valid_accounts import T1078ValidAccountsDetector


# ---------------------------------------------------------------------------
# Shared mock state manager
# ---------------------------------------------------------------------------
class MockStateManager:
    """Minimal stub for SecurityStateManager used across lateral movement tests."""

    def __init__(self, initial_state=None):
        self._state = initial_state or {}

    def get_latest_state(self, key):
        return self._state.get(key)

    def save_state(self, key, value, scan_id=None):
        self._state[key] = value


# ===========================================================================
# T1550 AlternateAuthDetector
# ===========================================================================
class TestT1550AlternateAuthDetectorInit(unittest.TestCase):
    """Tests that T1550AlternateAuthDetector initialises correctly."""

    def test_default_initialisation(self):
        detector = T1550AlternateAuthDetector()
        self.assertIsNotNone(detector.state_manager)
        self.assertEqual(detector.detector_name, "T1550AlternateAuthDetector")

    def test_custom_state_manager_accepted(self):
        sm = MockStateManager()
        detector = T1550AlternateAuthDetector(state_manager=sm)
        self.assertIs(detector.state_manager, sm)


class TestT1550MaskPath(unittest.TestCase):
    """Tests for the _mask_path helper."""

    def setUp(self):
        self.detector = T1550AlternateAuthDetector()

    def test_path_inside_project_is_relative(self):
        inside_path = self.detector.project_root / "some" / "file.txt"
        masked = self.detector._mask_path(inside_path)
        self.assertTrue(masked.startswith("./"))

    def test_path_outside_project_is_masked(self):
        outside_path = Path("/etc/passwd")
        masked = self.detector._mask_path(outside_path)
        self.assertIn("/", masked)
        self.assertIn("passwd", masked)


class TestT1550GetPermissions(unittest.TestCase):
    """Tests for the _get_permissions helper."""

    def setUp(self):
        self.detector = T1550AlternateAuthDetector()

    @patch("os.access", return_value=False)
    def test_inaccessible_file(self, _mock):
        result = self.detector._get_permissions(Path("/some/locked/file"))
        self.assertEqual(result, "inaccessible")

    @patch("os.access", return_value=True)
    def test_accessible_file_returns_mode(self, _mock):
        mock_path = MagicMock(spec=Path)
        mock_stat = MagicMock()
        mock_stat.st_mode = 0o100600
        mock_path.stat.return_value = mock_stat
        result = self.detector._get_permissions(mock_path)
        self.assertEqual(result, stat.S_IMODE(0o100600))


class TestT1550ScanCredentialFileLocations(unittest.TestCase):
    """Tests for _scan_credential_file_locations."""

    def setUp(self):
        self.detector = T1550AlternateAuthDetector()

    @patch("pathlib.Path.exists", return_value=False)
    def test_no_findings_when_files_absent(self, _mock):
        findings = self.detector._scan_credential_file_locations()
        self.assertEqual(findings, [])

    @patch("pathlib.Path.is_file", return_value=True)
    @patch("pathlib.Path.exists", return_value=True)
    @patch("os.access", return_value=True)
    def test_finding_returned_when_ssh_key_present(self, _mock_access, _mock_exists, _mock_isfile):
        with patch.object(
            self.detector,
            "_get_permissions",
            return_value=0o600,
        ):
            findings = self.detector._scan_credential_file_locations()
        self.assertGreater(len(findings), 0)
        types = [f["type"] for f in findings]
        self.assertIn("file_based_credential", types)


class TestT1550RunChecks(unittest.TestCase):
    """Tests for the run_checks method."""

    def setUp(self):
        self.detector = T1550AlternateAuthDetector()

    def test_run_checks_returns_expected_keys(self):
        with patch.object(self.detector, "_scan_credential_file_locations", return_value=[]):
            with patch.object(self.detector, "_scan_config_files", return_value=[]):
                with patch.object(self.detector, "_check_system_caches", return_value=[]):
                    result = self.detector.run_checks(scan_path=".")
        self.assertIn("findings", result)
        self.assertIn("summary", result)
        self.assertIn("total_findings", result["summary"])
        self.assertIn("high_risk_findings", result["summary"])

    def test_run_checks_counts_high_risk_correctly(self):
        mock_findings = [
            {"type": "file_based_credential", "risk_level": "high"},
            {"type": "config_file_risk", "risk_level": "high"},
            {"type": "credential_cache_present", "risk_level": "low"},
        ]
        with patch.object(self.detector, "_scan_credential_file_locations", return_value=mock_findings):
            with patch.object(self.detector, "_scan_config_files", return_value=[]):
                with patch.object(self.detector, "_check_system_caches", return_value=[]):
                    result = self.detector.run_checks(scan_path=".")
        self.assertEqual(result["summary"]["total_findings"], 3)
        self.assertEqual(result["summary"]["high_risk_findings"], 2)


# ===========================================================================
# T1021 RemoteServicesDetector
# ===========================================================================
class TestT1021RemoteServicesDetectorInit(unittest.TestCase):
    """Tests that T1021RemoteServicesDetector initialises correctly."""

    def test_default_initialisation(self):
        detector = T1021RemoteServicesDetector()
        self.assertIsNotNone(detector.state_manager)
        self.assertEqual(detector.detector_name, "T1021RemoteServicesDetector")

    def test_custom_state_manager_accepted(self):
        sm = MockStateManager()
        detector = T1021RemoteServicesDetector(state_manager=sm)
        self.assertIs(detector.state_manager, sm)


class TestT1021RunCommand(unittest.TestCase):
    """Tests for the _run_command helper."""

    def setUp(self):
        self.detector = T1021RemoteServicesDetector()

    @patch("subprocess.run")
    def test_successful_command_returns_lines(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="line1\nline2", stderr="")
        result = self.detector._run_command(["echo", "hello"])
        self.assertEqual(result, ["line1", "line2"])

    @patch("subprocess.run", side_effect=Exception("timeout"))
    def test_exception_returns_empty_list(self, _mock):
        result = self.detector._run_command(["bad_command"])
        self.assertEqual(result, [])


class TestT1021GetSshSessionsLinux(unittest.TestCase):
    """Tests for _get_ssh_sessions_linux."""

    def setUp(self):
        self.detector = T1021RemoteServicesDetector()
        self.detector.platform = "linux"

    @patch("pathlib.Path.exists", return_value=False)
    def test_returns_empty_when_log_absent(self, _mock):
        result = self.detector._get_ssh_sessions_linux()
        self.assertEqual(result, [])

    @patch("pathlib.Path.exists", return_value=True)
    def test_parses_accepted_password_line(self, _mock):
        log_line = "Jan 20 10:00:00 host sshd[1234]: Accepted password for alice from 10.0.0.5 port 22 ssh2\n"
        with patch("builtins.open", mock_open(read_data=log_line)):
            result = self.detector._get_ssh_sessions_linux()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["user"], "alice")
        self.assertEqual(result[0]["source"], "10.0.0.5")
        self.assertEqual(result[0]["service"], "SSH")

    @patch("pathlib.Path.exists", return_value=True)
    def test_ignores_non_ssh_lines(self, _mock):
        log_line = "Jan 20 10:00:00 host sudo: alice ran a command\n"
        with patch("builtins.open", mock_open(read_data=log_line)):
            result = self.detector._get_ssh_sessions_linux()
        self.assertEqual(result, [])


class TestT1021MapLateralPaths(unittest.TestCase):
    """Tests for _map_lateral_paths."""

    def setUp(self):
        self.detector = T1021RemoteServicesDetector()

    def test_rdp_session_creates_path(self):
        sessions = [{"service": "RDP", "source": "192.168.1.5", "destination": "192.168.1.10", "user": "admin"}]
        paths = self.detector._map_lateral_paths(sessions, [])
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["from"], "192.168.1.5")
        self.assertEqual(paths[0]["via"], "RDP")

    def test_ssh_session_creates_path(self):
        sessions = [{"service": "SSH", "source": "10.0.0.1", "destination": "10.0.0.2", "user": "root"}]
        paths = self.detector._map_lateral_paths(sessions, [])
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["via"], "SSH")

    def test_no_sessions_no_paths(self):
        paths = self.detector._map_lateral_paths([], [])
        self.assertEqual(paths, [])


class TestT1021AnalyzeNetworkData(unittest.TestCase):
    """Tests for analyze_network_data (also aliased as run_checks)."""

    def setUp(self):
        self.sm = MockStateManager()
        self.detector = T1021RemoteServicesDetector(state_manager=self.sm)

    def test_returns_expected_keys(self):
        with patch.object(self.detector, "_get_ssh_sessions_linux", return_value=[]):
            with patch.object(self.detector, "_get_rdp_sessions_windows", return_value=[]):
                with patch.object(self.detector, "_analyze_saved_credentials", return_value=[]):
                    result = self.detector.analyze_network_data()
        for key in ("newly_detected_sessions", "all_current_sessions", "saved_credentials", "potential_lateral_paths"):
            self.assertIn(key, result)

    def test_new_session_detected_vs_baseline(self):
        existing = [{"service": "SSH", "source": "10.0.0.1", "user": "alice", "destination": "host"}]
        new_session = {"service": "SSH", "source": "10.0.0.99", "user": "bob", "destination": "host"}
        self.sm._state["T1021RemoteServicesDetector"] = {"sessions": existing}
        with patch.object(self.detector, "_get_ssh_sessions_linux", return_value=[new_session]):
            with patch.object(self.detector, "_get_rdp_sessions_windows", return_value=[]):
                with patch.object(self.detector, "_analyze_saved_credentials", return_value=[]):
                    result = self.detector.analyze_network_data()
        self.assertEqual(len(result["newly_detected_sessions"]), 1)
        self.assertEqual(result["newly_detected_sessions"][0]["user"], "bob")

    def test_run_checks_alias_works(self):
        """run_checks should be an alias for analyze_network_data."""
        with patch.object(self.detector, "_get_ssh_sessions_linux", return_value=[]):
            with patch.object(self.detector, "_get_rdp_sessions_windows", return_value=[]):
                with patch.object(self.detector, "_analyze_saved_credentials", return_value=[]):
                    result = self.detector.run_checks()
        self.assertIn("all_current_sessions", result)


# ===========================================================================
# T1078 ValidAccountsDetector
# ===========================================================================
class TestT1078ValidAccountsDetectorInit(unittest.TestCase):
    """Tests that T1078ValidAccountsDetector initialises correctly."""

    def test_default_initialisation(self):
        detector = T1078ValidAccountsDetector()
        self.assertIsNotNone(detector.state_manager)
        self.assertEqual(detector.detector_name, "T1078ValidAccountsDetector")

    def test_custom_state_manager_accepted(self):
        sm = MockStateManager()
        detector = T1078ValidAccountsDetector(state_manager=sm)
        self.assertIs(detector.state_manager, sm)


class TestT1078RunChecks(unittest.TestCase):
    """Tests for T1078ValidAccountsDetector.run_checks."""

    def setUp(self):
        self.sm = MockStateManager()
        self.detector = T1078ValidAccountsDetector(state_manager=self.sm)

    def _make_t1021_results(self, sessions):
        return {"all_current_sessions": sessions}

    def test_returns_expected_keys(self):
        result = self.detector.run_checks(
            t1087_results={},
            t1021_results=self._make_t1021_results([]),
        )
        for key in ("suspicious_accounts", "weak_password_accounts", "privilege_escalation_risks"):
            self.assertIn(key, result)

    def test_off_hours_access_flagged(self):
        """A session at 03:00 should be flagged as off-hours access."""
        sessions = [
            {
                "service": "SSH",
                "source": "10.0.0.5",
                "user": "svc_backup",
                "timestamp": "2024-01-20T03:15:00",
            }
        ]
        result = self.detector.run_checks(
            t1087_results={},
            t1021_results=self._make_t1021_results(sessions),
        )
        suspicious_users = [a["username"] for a in result["suspicious_accounts"]]
        self.assertIn("svc_backup", suspicious_users)

    def test_new_hosts_accessed_flagged(self):
        """Accessing more than 2 new systems should be flagged."""
        # Establish a baseline with no previous hosts
        self.sm._state["T1078ValidAccountsDetector"] = {"account_activity": {}}
        sessions = [
            {"service": "RDP", "source": f"192.168.1.{i}", "user": "admin", "timestamp": "2024-01-20T10:00:00"}
            for i in range(1, 5)  # 4 new hosts
        ]
        result = self.detector.run_checks(
            t1087_results={},
            t1021_results=self._make_t1021_results(sessions),
        )
        suspicious_users = [a["username"] for a in result["suspicious_accounts"]]
        self.assertIn("admin", suspicious_users)

    def test_no_sessions_no_suspicious_accounts(self):
        result = self.detector.run_checks(
            t1087_results={},
            t1021_results=self._make_t1021_results([]),
        )
        self.assertEqual(result["suspicious_accounts"], [])

    def test_state_saved_after_run(self):
        sessions = [
            {"service": "SSH", "source": "10.0.0.1", "user": "alice", "timestamp": "2024-01-20T10:00:00"}
        ]
        self.detector.run_checks(
            t1087_results={},
            t1021_results=self._make_t1021_results(sessions),
        )
        saved = self.sm.get_latest_state("T1078ValidAccountsDetector")
        self.assertIsNotNone(saved)
        self.assertIn("account_activity", saved)


if __name__ == "__main__":
    unittest.main()
