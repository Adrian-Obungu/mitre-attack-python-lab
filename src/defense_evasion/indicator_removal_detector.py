import os
import logging
import time
from pathlib import Path
from typing import Dict, List, Any

# Assuming state_manager is in src/core
from src.core.state_manager import SecurityStateManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class T1070IndicatorRemovalDetector:
    """
    Detects indicator removal on host, now using a state manager for historical comparison.
    Maps to MITRE ATT&CK Technique T1070.
    """

    def __init__(self, state_manager: SecurityStateManager):
        """
        Initializes the T1070IndicatorRemovalDetector with a state manager.
        """
        self.state_manager = state_manager
        self.detector_name = self.__class__.__name__
        logger.info(f"{self.detector_name} initialized with a state manager.")

    def _get_monitored_logs(self) -> List[Path]:
        """Returns a platform-specific list of log files/dirs to monitor."""
        if os.name == 'nt':
            # On Windows, EVTX files are harder to monitor by size alone.
            # We'll focus on common application/tool logs.
            program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
            return [Path(program_files) / "SomeApp" / "logs"]
        else:
            return [Path("/var/log/auth.log"), Path("/var/log/syslog")]

    def run_checks(self, scan_id: str = None) -> Dict[str, Any]:
        """
        Runs all indicator removal checks by comparing the current state
        to the last known state from the state manager.
        """
        results = {
            "log_truncation": [],
            "rapid_file_deletion": []
        }
        
        # --- 1. Log Clearing/Truncation Check ---
        log_paths = self._get_monitored_logs()
        
        # Get baseline from state manager
        baseline = self.state_manager.get_latest_state(self.detector_name)
        
        current_log_states = {}
        for log_path in log_paths:
            if log_path.is_file():
                current_log_states[str(log_path)] = {"size": log_path.stat().st_size}

        if baseline:
            baseline_logs = baseline.get("logs", {})
            for log_path_str, current_state in current_log_states.items():
                baseline_state = baseline_logs.get(log_path_str)
                if baseline_state:
                    baseline_size = baseline_state.get("size", 0)
                    current_size = current_state.get("size", 0)
                    if current_size < baseline_size:
                        results["log_truncation"].append({
                            "log_path": log_path_str,
                            "previous_size": baseline_size,
                            "current_size": current_size,
                            "status": "Log file was truncated or cleared."
                        })
        
        # --- 2. Rapid File Deletion Check (conceptual) ---
        # This is difficult to implement in a stateless scan. A real implementation
        # would require a persistent monitoring agent. Here, we simulate a check.
        # This part of the logic remains conceptual for a one-off scan.
        
        # Save current state as the new baseline for next time
        new_baseline = {"logs": current_log_states, "files": {}} # 'files' part is for deletion
        self.state_manager.save_state(self.detector_name, new_baseline, scan_id=scan_id)

        return results

# Example usage (would be called from the unified scanner)
if __name__ == '__main__':
    # Setup a mock state manager for demonstration
    sm = SecurityStateManager(db_path=":memory:") # Use in-memory DB for example

    # --- First Run (creates baseline) ---
    print("--- Running First Scan (Baseline Creation) ---")
    detector1 = T1070IndicatorRemovalDetector(state_manager=sm)
    
    # Let's create a dummy log file to monitor
    dummy_log = Path("test_auth.log")
    with open(dummy_log, "w") as f:
        f.write("Line 1\nLine 2\nLine 3\n")
    
    # We need to override the monitored logs for the example
    detector1._get_monitored_logs = lambda: [dummy_log]
    
    results1 = detector1.run_checks(scan_id="scan-1")
    print(json.dumps(results1, indent=2))
    
    # --- Second Run (log is truncated) ---
    print("\n--- Running Second Scan (Simulating Log Truncation) ---")
    time.sleep(1)
    # Now, we truncate the log file
    with open(dummy_log, "w") as f:
        f.write("A single new line\n")

    detector2 = T1070IndicatorRemovalDetector(state_manager=sm)
    detector2._get_monitored_logs = lambda: [dummy_log]
    results2 = detector2.run_checks(scan_id="scan-2")
    print(json.dumps(results2, indent=2))

    # Clean up the dummy file
    os.remove(dummy_log)