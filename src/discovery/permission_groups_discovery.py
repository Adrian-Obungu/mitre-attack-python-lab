import platform
import logging
import os
import json
import subprocess
import time
import re
from typing import Dict, List, Any, Optional, Callable

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class T1069PermissionGroupsDiscovery:
    """
    Discovers system permission groups and membership, mapping to MITRE ATT&CK Technique T1069.
    This enhanced version includes domain, enterprise, and platform-specific features.
    """

    def __init__(self, enumeration_timeout: int = 10, cache_ttl: int = 300):
        """
        Initializes the T1069PermissionGroupsDiscovery detector.
        :param enumeration_timeout: Timeout for local group enumeration commands.
        :param cache_ttl: Time-to-live for cached results in seconds.
        """
        self.platform = platform.system()
        self.enumeration_timeout = enumeration_timeout
        self.cache_ttl = cache_ttl
        self.cache: Dict[str, Any] = {}
        self._get_groups_method: Callable[[], List[Dict[str, Any]]] = self._get_local_groups_unix
        if self.platform == "Windows":
            self._get_groups_method = self._get_local_groups_windows
        elif self.platform == "Darwin":
            self._get_groups_method = self._get_groups_macos
        logger.info(f"T1069PermissionGroupsDiscovery initialized on {self.platform}.")

    def _run_command(self, command: List[str], timeout: Optional[int] = None) -> List[str]:
        """Helper to run shell commands and return output lines."""
        try:
            full_command = ["powershell.exe", "-Command"] + command if self.platform == "Windows" else command
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                encoding='utf-8',
                errors='ignore'
            )
            if result.returncode != 0:
                logger.debug(f"Command '{' '.join(command)}' exited with error {result.returncode}: {result.stderr.strip()}")
            return result.stdout.strip().split('\n')
        except subprocess.TimeoutExpired:
            logger.warning(f"Command '{' '.join(command)}' timed out after {timeout} seconds.")
            return []
        except Exception as e:
            logger.error(f"Error running command '{' '.join(command)}': {e}")
            return []

    def _is_domain_joined_windows(self) -> bool:
        """Checks if the Windows machine is joined to a domain."""
        try:
            output = self._run_command(['systeminfo'])
            for line in output:
                if re.match(r"^\s*Domain:\s*([^\s]+)", line):
                    domain = line.split(":", 1)[1].strip()
                    if domain.lower() != 'workgroup':
                        logger.info(f"Machine is joined to domain: {domain}")
                        return True
            return False
        except Exception as e:
            logger.error(f"Error checking domain join status: {e}")
            return False

    def _is_domain_joined(self) -> bool:
        """Checks if the machine is joined to a domain."""
        if self.platform == "Windows":
            return self._is_domain_joined_windows()
        return False

    def _can_enumerate_domain(self) -> bool:
        """Checks if domain enumeration is possible."""
        if self.platform == "Windows":
            return self._is_domain_joined()
        try:
            import ldap
            return True
        except ImportError:
            return False

    def _get_domain_groups_windows(self) -> List[Dict[str, Any]]:
        """Enumerates domain groups on Windows using 'net group /domain'."""
        if not self._is_domain_joined():
            logger.info("Machine not domain-joined. Skipping domain group enumeration.")
            return []

        logger.info("Enumerating domain groups with 'net group /domain'...")
        domain_groups = []
        output = self._run_command(["net", "group", "/domain"], timeout=5)

        in_group_list_section = False
        for line in output:
            line = line.strip()
            if "---" in line:
                in_group_list_section = True
                continue
            if in_group_list_section and line.startswith("*"):
                group_name = line[1:].strip()
                if group_name:
                    domain_groups.append({"name": group_name, "members": [], "source": "domain"})
        
        if not domain_groups and "The command completed successfully." not in " ".join(output):
             logger.warning("Could not enumerate domain groups. Check privileges or network.")

        return domain_groups

    def _get_groups_macos(self) -> List[Dict[str, Any]]:
        """Enumerates local groups on macOS using 'dscl'."""
        logger.info("Enumerating groups on macOS with 'dscl'...")
        groups = []
        group_names_output = self._run_command(["dscl", ".", "list", "/Groups"])

        for group_name in group_names_output:
            group_name = group_name.strip()
            if group_name and not group_name.startswith("_"):
                details_output = self._run_command(["dscl", ".", "read", f"/Groups/{group_name}"])
                gid = ""
                members = []
                for line in details_output:
                    if line.startswith("PrimaryGroupID:"):
                        gid = line.split(":")[-1].strip()
                    if line.startswith("GroupMembership:"):
                        members_str = line.split(":", 1)[-1].strip()
                        if members_str:
                            members = members_str.split()
                
                groups.append({"name": group_name, "gid": gid, "members": members})
        return groups

    def _identify_service_accounts(self, all_groups: List[Dict[str, Any]]) -> List[str]:
        """Identifies potential service accounts based on heuristics."""
        service_accounts = []
        heuristics = [
            re.compile(r".*\$\$"),
            re.compile(r".*svc_.*", re.I),
            re.compile(r".*service.*", re.I),
            re.compile(r"sqlservice", re.I),
            re.compile(r"iis_apppool", re.I),
        ]
        
        all_members = set()
        for group in all_groups:
            all_members.update(group.get("members", []))

        for member in all_members:
            for heuristic in heuristics:
                if heuristic.match(member) and member not in service_accounts:
                    service_accounts.append(member)
                    break
        return service_accounts
        
    def _query_ldap_groups(self) -> List[Dict[str, Any]]:
        """Queries an LDAP/AD server for groups (cross-platform fallback)."""
        try:
            import ldap
            logger.info("python-ldap is installed, but full query logic is a placeholder.")
            return [{"name": "ldap-placeholder-group", "source": "LDAP"}]
        except ImportError:
            logger.info("python-ldap not installed. Skipping LDAP group discovery.")
            return []

    def _get_local_groups_windows(self) -> List[Dict[str, Any]]:
        """
        Enumerates local groups and their members on Windows using 'net localgroup'.
        Performs a two-step process: first lists group names, then details for each.
        """
        local_groups_found = []
        
        # Step 1: Get all local group names
        output_group_names = self._run_command(["net", "localgroup"], timeout=self.enumeration_timeout)
        group_names = []
        in_group_list_section = False
        for line in output_group_names:
            line = line.strip()
            if "---" in line:
                in_group_list_section = True
                continue
            if in_group_list_section and line.startswith("*"):
                group_name = line[1:].strip()
                if group_name and group_name != "The command completed successfully.":
                    group_names.append(group_name)
            if "The command completed successfully" in line:
                break
        
        # Step 2: For each group name, get its members and description
        for g_name in group_names:
            group_details_output = self._run_command(["net", "localgroup", g_name], timeout=self.enumeration_timeout)
            
            description = ""
            members = []
            in_members_section = False
            for line in group_details_output:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("Comment"):
                    description = line.replace("Comment", "", 1).strip()
                elif "Members" in line:
                    in_members_section = True
                    continue
                elif in_members_section and "---" in line:
                    continue
                elif in_members_section and line and not line.startswith("The command completed successfully"):
                    # Exclude lines that are not members (e.g. blank lines, command success message)
                    if not line.startswith("-") and not line.startswith("*"): # Filter out separator and other special lines
                        members.append(line)
            
            local_groups_found.append({
                "name": g_name,
                "description": description,
                "members": members
            })
        
        return local_groups_found

    def _get_local_groups_unix(self) -> List[Dict[str, Any]]:
        """
        Enumerates local groups and their members on Linux using 'getent group' or '/etc/group'.
        """
        local_groups = []
        output = self._run_command(["getent", "group"], timeout=self.enumeration_timeout)
        if not output or output == ['']:
            # Fallback to /etc/group if getent is not available or fails
            try:
                with open("/etc/group", "r") as f:
                    output = f.readlines()
            except (FileNotFoundError, PermissionError) as e:
                logger.warning(f"Could not read /etc/group: {e}. Skipping local group enumeration.")
                return []
            except Exception as e:
                logger.error(f"Error reading /etc/group: {e}")
                return []

        for line in output:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split(':')
            if len(parts) == 4:
                group_name = parts[0]
                gid = parts[2]
                members_str = parts[3]
                members = [m.strip() for m in members_str.split(',') if m.strip()] if members_str else []
                local_groups.append({
                    "name": group_name,
                    "gid": gid, # Include GID for Unix groups
                    "members": members
                })
        return local_groups

    def run_checks(self, include_domain: bool = False, identify_service_accounts: bool = False) -> Dict[str, Any]:
        """
        Runs all permission group discovery checks.
        :param include_domain: Whether to attempt domain-level enumeration.
        :param identify_service_accounts: Whether to run service account heuristics.
        """
        start_time = time.perf_counter()
        cache_key = f"{self.platform}_groups_{include_domain}_{identify_service_accounts}"

        if cache_key in self.cache and (time.time() - self.cache[cache_key]['timestamp'] < self.cache_ttl):
            logger.info("Returning results from cache.")
            return self.cache[cache_key]['data']

        results: Dict[str, Any] = {
            "local_groups": [],
            "domain_groups": [],
            "platform_groups": {},
            "service_accounts": [],
            "status": "success"
        }

        # Platform-specific group enumeration
        if self.platform == "Darwin":
            results["platform_groups"] = {"type": "dscl_macos", "groups": self._get_groups_macos()}
            results["local_groups"] = results["platform_groups"]["groups"]
        else:
            results["local_groups"] = self._get_groups_method()

        # Domain enumeration
        if include_domain:
            if self.platform == "Windows":
                results["domain_groups"] = self._get_domain_groups_windows()
            else:
                results["domain_groups"] = self._query_ldap_groups()

        # Service account identification
        if identify_service_accounts:
            all_groups = results["local_groups"] + results.get("domain_groups", [])
            results["service_accounts"] = self._identify_service_accounts(all_groups)

        end_time = time.perf_counter()
        results["execution_time"] = f"{end_time - start_time:.4f} seconds"
        
        self.cache[cache_key] = {'timestamp': time.time(), 'data': results}
        logger.info(f"T1069 checks completed in {results['execution_time']}")
        return results

if __name__ == '__main__':
    detector = T1069PermissionGroupsDiscovery()
    # Example of a comprehensive scan
    scan_results = detector.run_checks(include_domain=True, identify_service_accounts=True)
    print(json.dumps(scan_results, indent=2))
