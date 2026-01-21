import logging
import platform
from datetime import datetime
from typing import Dict, List, Any, Optional

from src.core.state_manager import SecurityStateManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class T1078ValidAccountsDetector:
    """
    Identifies potentially compromised or misused valid accounts by analyzing
    behavior patterns, mapping to MITRE ATT&CK Technique T1078.
    """

    def __init__(self, state_manager: SecurityStateManager):
        """
        Initializes the T1078ValidAccountsDetector with a state manager.
        """
        self.state_manager = state_manager
        self.detector_name = self.__class__.__name__
        self.platform = platform.system()
        logger.info(f"{self.detector_name} initialized on {self.platform}.")

    def _is_off_hours(self, timestamp: datetime) -> bool:
        """Checks if a timestamp is outside of typical 9-5 business hours."""
        return timestamp.weekday() >= 5 or not (9 <= timestamp.hour < 17)

    def _check_password_policies(self) -> List[Dict[str, Any]]:
        """
        Performs a read-only check for weak password policies.
        This is a placeholder for a more in-depth implementation.
        """
        weak_policies = []
        if self.platform == "Windows":
            # This would parse 'net accounts' output
            pass
        elif self.platform == "Linux":
            # This would involve checking /etc/login.defs or pam.d configs
            pass
        
        # Example placeholder finding
        # weak_policies.append({"username": "guest", "reason": "password_not_required"})
        return weak_policies

    def run_checks(
        self,
        t1087_results: Dict[str, Any],
        t1021_results: Dict[str, Any],
        scan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyzes account and session data for suspicious patterns.

        :param t1087_results: Results from T1087AccountDiscovery.
        :param t1021_results: Results from T1021RemoteServicesDetector.
        :param scan_id: An optional ID for the scan.
        """
        suspicious_accounts = []
        
        # --- 1. Correlate account and session data ---
        account_activity = {}
        all_sessions = t1021_results.get("all_current_sessions", [])
        
        for session in all_sessions:
            user = session.get("user")
            if not user: continue

            if user not in account_activity:
                account_activity[user] = {"sessions": [], "source_hosts": set()}
            
            account_activity[user]["sessions"].append(session)
            account_activity[user]["source_hosts"].add(session.get("source"))

        # --- 2. Analyze for anomalies ---
        baseline_data = self.state_manager.get_latest_state(self.detector_name) or {}
        previous_activity = baseline_data.get("account_activity", {})

        for user, activity in account_activity.items():
            reasons = []
            
            # Anomaly: Sudden increase in activity or new systems accessed
            previous_user_activity = previous_activity.get(user, {})
            previous_hosts = set(previous_user_activity.get("source_hosts", []))
            newly_accessed_hosts = activity["source_hosts"] - previous_hosts
            
            if len(newly_accessed_hosts) > 2: # Arbitrary threshold
                reasons.append(f"Accessed {len(newly_accessed_hosts)} new systems.")

            # Anomaly: Off-hours access
            for session in activity["sessions"]:
                try:
                    # Attempt to parse timestamp (format may vary)
                    session_time = datetime.fromisoformat(session.get("timestamp"))
                    if self._is_off_hours(session_time):
                        reasons.append("off_hours_access")
                        break 
                except (ValueError, TypeError):
                    pass # Couldn't parse timestamp

            if reasons:
                suspicious_accounts.append({
                    "username": user,
                    "reasons": reasons,
                    "recent_activity": list(activity["source_hosts"]),
                    "confidence_score": 0.7 
                })

        # --- 3. Password Policy and Privilege Risks ---
        weak_password_accounts = self._check_password_policies()
        
        # Placeholder for privilege escalation path analysis
        privilege_escalation_risks = []
        
        # --- 4. Save new state ---
        # We need to merge current activity with historical for a complete picture
        for user, activity in account_activity.items():
             # Convert sets to lists for JSON serialization
            activity['source_hosts'] = list(activity['source_hosts'])
        self.state_manager.save_state(self.detector_name, {"account_activity": account_activity}, scan_id=scan_id)

        return {
            "suspicious_accounts": suspicious_accounts,
            "weak_password_accounts": weak_password_accounts,
            "privilege_escalation_risks": privilege_escalation_risks
        }

if __name__ == '__main__':
    # Example for standalone execution
    class MockStateManager:
        def save_state(self, *args, **kwargs): print(f"Mock SM: Saving state for {args[0]}")
        def get_latest_state(self, *args, **kwargs): 
            print(f"Mock SM: Getting state for {args[0]}")
            return None # No baseline for first run

    mock_t1087_results = {"local_users": ["admin", "guest", "svc_backup"], "domain_users": []}
    mock_t1021_results = {
        "all_current_sessions": [
            {"service": "RDP", "source": "192.168.1.100", "user": "domain\admin", "timestamp": "2024-01-20T22:05:00"},
            {"service": "SSH", "source": "10.0.0.5", "user": "svc_backup", "timestamp": "2024-01-20T03:15:00"}
        ]
    }

    detector = T1078ValidAccountsDetector(state_manager=MockStateManager())
    results = detector.run_checks(t1087_results=mock_t1087_results, t1021_results=mock_t1021_results)
    print(json.dumps(results, indent=2))
