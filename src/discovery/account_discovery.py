import platform
import logging
import os
import time
import json
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class T1087AccountDiscovery:
    """
    Detects attempts to discover local and domain accounts, mapping to MITRE ATT&CK Technique T1087.
    """

    def __init__(self):
        """
        Initializes the T1087AccountDiscovery detector.
        """
        self.platform = platform.system()
        logger.info(f"T1087AccountDiscovery initialized on {self.platform}.")

    def _run_command(self, command: str) -> List[str]:
        """Helper to run shell commands and return output lines."""
        try:
            # Use powershell for Windows for better command execution
            if self.platform == "Windows":
                process = os.popen(f"powershell.exe -Command \"{command}\"")
            else:
                process = os.popen(command)
            output = process.read()
            process.close()
            return output.strip().split('\n')
        except Exception as e:
            logger.error(f"Error running command '{command}': {e}")
            return []

    def get_local_users_windows(self) -> List[str]:
        """Retrieves local user accounts on Windows."""
        users = []
        output = self._run_command("net user")
        
        user_list_started = False
        for line in output:
            if "---" in line: # Separator line
                user_list_started = True
                continue
            if "The command completed successfully" in line: # Stop processing here
                break
            if user_list_started and line.strip():
                parts = line.split()
                for user in parts:
                    if user: # Only add non-empty strings
                        users.append(user.strip())
        return users

    def get_domain_users_windows(self) -> List[str]:
        """Retrieves domain user accounts on Windows (simplified)."""
        users = []
        # This is a highly simplified approach. A full implementation would involve
        # LDAP queries or more advanced AD tools.
        output = self._run_command("net group \"Domain Users\"")
        
        user_list_started = False
        for line in output:
            if "---" in line: # Separator line
                user_list_started = True
                continue
            if "The command completed successfully" in line: # Stop processing here
                break
            if user_list_started and line.strip():
                parts = line.split()
                for user in parts:
                    if user: # Only add non-empty strings
                        users.append(user.strip())
        return users


    def get_users_unix(self) -> Dict[str, List[str]]:
        """Retrieves user accounts on Linux/macOS using getent or /etc/passwd."""
        local_users = []
        system_accounts = []

        try:
            # Try using getent for more comprehensive and accurate user info
            output = self._run_command("getent passwd")
            if output:
                for line in output:
                    if line.strip():
                        parts = line.split(':')
                        username = parts[0]
                        uid = int(parts[2])
                        if uid >= 1000:  # Common heuristic for regular users on Linux
                            local_users.append(username)
                        else:
                            system_accounts.append(username)
                return {"local_users": local_users, "system_accounts": system_accounts}
        except Exception as e:
            logger.warning(f"getent command failed or not found: {e}. Falling back to /etc/passwd.")

        # Fallback to parsing /etc/passwd if getent fails or is unavailable
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.split(':')
                        username = parts[0]
                        uid = int(parts[2])
                        if uid >= 1000:
                            local_users.append(username)
                        else:
                            system_accounts.append(username)
        except FileNotFoundError:
            logger.error("/etc/passwd not found. Cannot enumerate users.")
        except PermissionError:
            logger.error("Permission denied to read /etc/passwd.")
        except Exception as e:
            logger.error(f"Error parsing /etc/passwd: {e}")
            
        return {"local_users": local_users, "system_accounts": system_accounts}

    def run_checks(self) -> Dict[str, Any]:
        """
        Runs all account discovery checks and returns results.
        """
        start_time = time.perf_counter()
        
        results: Dict[str, Any] = {
            "local_users": [],
            "domain_users": [],
            "system_accounts": [],
            "status": "success"
        }

        if self.platform == "Windows":
            results["local_users"] = self.get_local_users_windows()
            results["domain_users"] = self.get_domain_users_windows()
            # On Windows, system accounts are often special UIDs/GIDs not easily
            # distinguishable via 'net user'. Leaving this empty for now.
        elif self.platform in ["Linux", "Darwin"]: # Darwin is macOS
            unix_users = self.get_users_unix()
            results["local_users"] = unix_users.get("local_users", [])
            results["system_accounts"] = unix_users.get("system_accounts", [])
        else:
            results["status"] = "skipped"
            results["message"] = f"Unsupported platform: {self.platform}"
            logger.warning(results["message"])

        end_time = time.perf_counter()
        results["execution_time"] = f"{end_time - start_time:.4f} seconds"
        
        logger.info(f"T1087 Account Discovery checks completed in {results['execution_time']}")
        return results

if __name__ == '__main__':
    detector = T1087AccountDiscovery()
    results = detector.run_checks()
    print(json.dumps(results, indent=2))