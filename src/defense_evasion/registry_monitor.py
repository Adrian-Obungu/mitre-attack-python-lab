import platform
import logging
from src.utils.logging_config import setup_logging, JsonFormatter
import json
from typing import Dict, List, Any, Optional

from src.core.state_manager import SecurityStateManager

# Conditional import for winreg
if platform.system() == "Windows":
    import winreg
else:
    winreg = None
logger = logging.getLogger(__name__)
if not any(isinstance(h, JsonFormatter) for h in logger.handlers):
    setup_logging(level=logging.INFO, json_format=True)

class T1112RegistryMonitor:
    """
    Monitors the Windows registry for suspicious modifications using a state manager,
    mapping to MITRE ATT&CK Technique T1112.
    """

    def __init__(self, state_manager: Optional[SecurityStateManager] = None):
        """
        Initializes the T1112RegistryMonitor.

        Args:
            state_manager: An optional ``SecurityStateManager`` instance used to
                persist scan state between runs.  When ``None`` a new in-memory
                manager is created automatically so the class can be instantiated
                without arguments (e.g. in unit tests).
        """
        self.state_manager = state_manager if state_manager is not None else SecurityStateManager()
        self.detector_name = self.__class__.__name__
        if platform.system() != "Windows":
            logger.warning("Registry monitoring is only available on Windows. This module will run in a degraded state.")
        
        if winreg:
            self.keys_to_monitor = {
                "HKCU_Run": (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                "HKLM_Run": (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                "HKLM_Winlogon": (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            }
        else:
            self.keys_to_monitor = {}
        # ``baseline`` holds the last-known-good snapshot for quick comparisons.
        self.baseline: Dict[str, Any] = {}
        logger.info(f"{self.detector_name} initialized.")

    def _get_key_values(self, hkey, subkey_path: str) -> Dict[str, Any]:
        """Retrieves all values from a given registry key."""
        if not winreg: return {}
        values = {}
        try:
            with winreg.OpenKey(hkey, subkey_path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        values[name] = str(value) # Ensure value is serializable
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            logger.debug(f"Registry key not found: {subkey_path}")
        except Exception as e:
            logger.error(f"Error reading registry key {subkey_path}: {e}")
        return values

    def _create_snapshot(self) -> Dict[str, Any]:
        """Creates a snapshot of the configured registry keys."""
        snapshot = {}
        for name, (hkey, path) in self.keys_to_monitor.items():
            snapshot[name] = self._get_key_values(hkey, path)
        return snapshot

    def scan_persistence_keys(self) -> Dict[str, Any]:
        """Returns a snapshot of the configured persistence registry keys.

        On non-Windows platforms an empty dict is returned immediately.
        """
        if not winreg:
            return {}
        return self._create_snapshot()

    def create_registry_snapshot(self, keys: Dict[str, Any]) -> Dict[str, Any]:
        """Creates a registry snapshot for the given *keys* mapping.

        ``keys`` is a dict of ``{label: (hkey_root, subkey_path)}``.
        Returns an empty dict on non-Windows platforms.
        """
        if not winreg:
            return {}
        snapshot: Dict[str, Any] = {}
        for name, (hkey, path) in keys.items():
            snapshot[name] = self._get_key_values(hkey, path)
        return snapshot

    def compare_registry_snapshot(
        self,
        baseline: Dict[str, Any],
        current: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Compares two registry snapshots and returns a list of change records.

        Each record contains at minimum ``change_type`` (``'added'``,
        ``'modified'``, or ``'removed'``), ``key_name``, and ``value_name``.
        Works on all platforms — the snapshots are plain Python dicts.
        """
        # Note: no winreg guard here; comparison operates on plain dicts and
        # must work cross-platform so that unit tests can exercise the logic.
        changes: List[Dict[str, Any]] = []
        all_keys = set(baseline.keys()) | set(current.keys())
        for key_name in all_keys:
            baseline_values = baseline.get(key_name, {})
            current_values = current.get(key_name, {})
            # Added / Modified
            for val_name, cur_val in current_values.items():
                if val_name not in baseline_values:
                    changes.append({
                        "change_type": "added",
                        "key_name": key_name,
                        "value_name": val_name,
                        "new_data": cur_val,
                    })
                elif cur_val != baseline_values[val_name]:
                    changes.append({
                        "change_type": "modified",
                        "key_name": key_name,
                        "value_name": val_name,
                        "old_data": baseline_values[val_name],
                        "new_data": cur_val,
                    })
            # Removed
            for val_name, old_val in baseline_values.items():
                if val_name not in current_values:
                    changes.append({
                        "change_type": "removed",
                        "key_name": key_name,
                        "value_name": val_name,
                        "old_data": old_val,
                    })
        return changes

    def save_snapshot(
        self,
        snapshot: Dict[str, Any],
        keys: Dict[str, Any],
        path: str,
    ) -> None:
        """Persists a snapshot dict to a JSON file at *path*."""
        data = {"keys": {k: list(v) for k, v in keys.items()}, "snapshot": snapshot}
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        logger.info(f"Snapshot saved to {path}.")

    def load_snapshot(self, path: str) -> Dict[str, Any]:
        """Loads a snapshot from a JSON file at *path*.

        Returns an empty dict if the file is missing or cannot be parsed.
        """
        try:
            with open(path, "r") as fh:
                return json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.warning(f"Could not load snapshot from {path}: {exc}")
            return {}
        except Exception as exc:
            logger.error(f"Unexpected error loading snapshot from {path}: {exc}")
            return {}

    def run_checks(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Scans registry persistence keys and compares them against a stored baseline.
        """
        if platform.system() != "Windows":
            return {"status": "skipped", "reason": "Not a Windows system."}

        current_snapshot = self._create_snapshot()
        baseline = self.state_manager.get_latest_state(self.detector_name)
        
        changes = []
        if baseline:
            baseline_snapshot = baseline.get("snapshot", {})
            # Compare logic
            for key_name, baseline_values in baseline_snapshot.items():
                current_values = current_snapshot.get(key_name, {})
                
                # Added/Modified
                for val_name, cur_val in current_values.items():
                    if val_name not in baseline_values:
                        changes.append({"key": key_name, "value": val_name, "change": "added", "new_data": cur_val})
                    elif cur_val != baseline_values[val_name]:
                        changes.append({"key": key_name, "value": val_name, "change": "modified", "old": baseline_values[val_name], "new": cur_val})

                # Removed
                for val_name, old_val in baseline_values.items():
                    if val_name not in current_values:
                         changes.append({"key": key_name, "value": val_name, "change": "removed", "old_data": old_val})

        # Save the current state for the next run
        self.state_manager.save_state(
            self.detector_name,
            {"snapshot": current_snapshot},
            scan_id=scan_id
        )

        return {"detected_changes": changes}

if __name__ == '__main__':
    sm = SecurityStateManager(db_path=":memory:")
    monitor = T1112RegistryMonitor(state_manager=sm) # type: ignore
    
    if platform.system() == "Windows":
        print("--- Running First Scan (Baseline) ---")
        results1 = monitor.run_checks(scan_id="scan-1")
        print(json.dumps(results1, indent=2))
        
        # Simulate a change by adding a fake startup entry
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
                winreg.SetValueEx(key, "MaliciousApp", 0, winreg.REG_SZ, "C:\\temp\\evil.exe")
            
            print("\n--- Running Second Scan (After Change) ---")
            results2 = monitor.run_checks(scan_id="scan-2")
            print(json.dumps(results2, indent=2))
        finally:
            # Cleanup
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, "MaliciousApp")
            except FileNotFoundError:
                pass
    else:
        print("This script provides a conceptual test; full functionality is Windows-only.")