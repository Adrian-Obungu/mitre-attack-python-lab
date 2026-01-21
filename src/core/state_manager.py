import sqlite3
import json
import time
import logging
from threading import Lock
from typing import Dict, Any, Optional, List

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurityStateManager:
    """
    Manages the state of security detectors for historical comparison.
    Uses an SQLite database for persistent, thread-safe storage.
    """

    def __init__(self, db_path: str = "security_state.db"):
        """
        Initializes the SecurityStateManager.
        :param db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self.lock = Lock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        """Initializes the database and creates the necessary tables."""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detector_states (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detector_name TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    state_data TEXT NOT NULL,
                    scan_id TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alert_timestamps (
                    technique_id TEXT PRIMARY KEY,
                    last_alert_timestamp REAL NOT NULL
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_detector_timestamp ON detector_states (detector_name, timestamp DESC)")
            self.conn.commit()

    def record_alert(self, technique_id: str, timestamp: float):
        """
        Records the timestamp of an alert for a given technique ID.
        :param technique_id: The technique ID (e.g., 'T1070').
        :param timestamp: The timestamp of the alert.
        """
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO alert_timestamps (technique_id, last_alert_timestamp) VALUES (?, ?)",
                (technique_id, timestamp)
            )
            self.conn.commit()

    def get_last_alert_time(self, technique_id: str) -> Optional[float]:
        """
        Retrieves the timestamp of the last alert for a given technique ID.
        :param technique_id: The technique ID (e.g., 'T1070').
        :return: The timestamp of the last alert, or None if no alert has been recorded.
        """
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT last_alert_timestamp FROM alert_timestamps WHERE technique_id = ?",
                (technique_id,)
            )
            row = cursor.fetchone()
        
        if row:
            return row[0]
        return None

    def save_state(self, detector_name: str, state: Dict[str, Any], scan_id: Optional[str] = None):
        """
        Saves the state of a detector to the database.
        :param detector_name: The name of the detector (e.g., 'T1070IndicatorRemovalDetector').
        :param state: The detector's state data as a dictionary.
        :param scan_id: An optional ID to associate with a specific scan.
        """
        if not isinstance(state, dict):
            raise TypeError("State must be a dictionary.")

        state_data_json = json.dumps(state)
        current_time = time.time()
        
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO detector_states (detector_name, timestamp, state_data, scan_id) VALUES (?, ?, ?, ?)",
                (detector_name, current_time, state_data_json, scan_id)
            )
            self.conn.commit()
        logger.info(f"Saved state for detector '{detector_name}'.")

    def get_latest_state(self, detector_name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the most recent state for a given detector.
        :param detector_name: The name of the detector.
        :return: The latest state data as a dictionary, or None if no state is found.
        """
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT state_data FROM detector_states WHERE detector_name = ? ORDER BY timestamp DESC LIMIT 1",
                (detector_name,)
            )
            row = cursor.fetchone()
        
        if row:
            return json.loads(row[0])
        return None

    def get_states_since(self, detector_name: str, timestamp: float) -> List[Dict[str, Any]]:
        """
        Retrieves all states for a detector since a given timestamp.
        """
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT state_data FROM detector_states WHERE detector_name = ? AND timestamp > ?",
                (detector_name, timestamp)
            )
            rows = cursor.fetchall()
        
        return [json.loads(row[0]) for row in rows]

    def cleanup(self, max_age_hours: int = 24):
        """
        Removes old state data from the database.
        :param max_age_hours: The maximum age of records to keep, in hours.
        """
        cutoff_timestamp = time.time() - (max_age_hours * 3600)
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM detector_states WHERE timestamp < ?", (cutoff_timestamp,))
            self.conn.commit()
            changes = self.conn.total_changes
        
        if changes > 0:
            logger.info(f"Cleaned up {changes} old state records.")

        # Here you could also implement logic to check db size and prune further if it exceeds 100MB
        # For simplicity, this is omitted for now.

    # Encryption/decryption placeholders
    def _encrypt_data(self, data: str) -> str:
        # Placeholder for encryption logic (e.g., using Fernet from cryptography library)
        logger.info("Data encryption is a placeholder and not yet implemented.")
        return data

    def _decrypt_data(self, data: str) -> str:
        # Placeholder for decryption logic
        return data

# Example usage
if __name__ == '__main__':
    state_manager = SecurityStateManager()
    
    # Example: Saving state for a detector
    detector_name = "T1070IndicatorRemovalDetector"
    current_state = {"files": ["file1.txt", "file2.log"], "timestamp": time.time()}
    state_manager.save_state(detector_name, current_state)
    
    # Example: Retrieving the latest state
    latest_state = state_manager.get_latest_state(detector_name)
    if latest_state:
        print(f"Latest state for {detector_name}:")
        print(json.dumps(latest_state, indent=2))
    else:
        print(f"No state found for {detector_name}.")

    # The cleanup runs on initialization, so old data would be purged.
