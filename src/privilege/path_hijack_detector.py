import os
import sys
import logging
from typing import List, Dict, Any, Optional

# Conditional import for winreg - only available on Windows
try:
    import winreg
except ImportError:
    winreg = None
    # logger.warning("winreg module not available. Registry-based checks will be skipped.")

logger = logging.getLogger(__name__)

class PathHijackDetector:
    """
    Detects potential Python Path Hijacking (T1073.001) vulnerabilities.
    """
    def __init__(self):
        self.findings = []
        
    def _is_windows(self) -> bool:
        """Checks if the current operating system is Windows."""
        return os.name == 'nt'

    def find_writable_directories_in_path(self, paths: List[str]) -> List[str]:
        """
        Identifies writable directories within a given list of paths.
        """
        writable_dirs = []
        for path_entry in paths:
            if not path_entry: # Skip empty path entries
                continue
            path_entry = os.path.normpath(path_entry)
            if not os.path.exists(path_entry):
                continue
            
            # Check if the directory is writable by the current user
            # On Windows, os.access(path, os.W_OK) might return true even if not fully writable
            # for unprivileged user. A more robust check might involve trying to create a file.
            if os.access(path_entry, os.W_OK) and os.path.isdir(path_entry):
                writable_dirs.append(path_entry)
        return writable_dirs

    def analyze_sys_path(self) -> List[Dict[str, Any]]:
        """
        Analyzes sys.path for writable directories, especially early entries.
        """
        if not self._is_windows():
            logger.info("Skipping sys.path analysis for hijacking: Not on Windows.")
            return []

        logger.info("Analyzing sys.path for writable directories...")
        sys_path_entries = sys.path
        writable_sys_paths = self.find_writable_directories_in_path(sys_path_entries)
        
        results = []
        for i, path in enumerate(sys_path_entries):
            if path in writable_sys_paths:
                results.append({
                    "path": path,
                    "position": i,
                    "is_writable": True,
                    "reason": "Directory is writable and appears in sys.path. Early writable entries are higher risk."
                })
            elif not os.path.exists(path):
                results.append({
                    "path": path,
                    "position": i,
                    "is_writable": False,
                    "reason": "Directory does not exist but is in sys.path. Could be a path hijacking vector if created by attacker."
                })
        return results
    
    def analyze_env_path(self) -> List[Dict[str, Any]]:
        """
        Analyzes the system's PATH environment variable for writable directories.
        """
        if not self._is_windows():
            logger.info("Skipping system PATH analysis for hijacking: Not on Windows.")
            return []

        logger.info("Analyzing system PATH environment variable...")
        path_env = os.environ.get("PATH", "").split(os.pathsep)
        writable_path_entries = self.find_writable_directories_in_path(path_env)

        results = []
        for i, path in enumerate(path_env):
            if path in writable_path_entries:
                results.append({
                    "path": path,
                    "position": i,
                    "is_writable": True,
                    "reason": "Directory is writable and appears in system PATH. Early writable entries are higher risk."
                })
            elif not os.path.exists(path):
                results.append({
                    "path": path,
                    "position": i,
                    "is_writable": False,
                    "reason": "Directory does not exist but is in system PATH. Could be a path hijacking vector if created by attacker."
                })
        return results

    def run_all_checks(self) -> List[Dict[str, Any]]:
        """
        Runs all checks for path hijacking and returns the raw findings.
        """
        all_findings = []
        all_findings.extend(self.analyze_sys_path())
        all_findings.extend(self.analyze_env_path())
        return all_findings
