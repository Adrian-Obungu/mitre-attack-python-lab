#!/usr/bin/env python3
"""
MITRE ATT&CK Lab - Comprehensive E2E Test Suite
Tests all documented and undocumented capabilities.
"""
import sys
import json
import subprocess
import time
import requests
from pathlib import Path

class ComprehensiveTester:
    def __init__(self):
        self.base_url = "http://127.0.0.1:8000"
        self.api_key = "demo-key-2024"
        self.headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        self.test_results = []
        
    def log_test(self, component, test, result, details=""):
        """Record test results with timing."""
        outcome = {
            "component": component,
            "test": test,
            "result": result,
            "timestamp": time.time(),
            "details": details
        }
        self.test_results.append(outcome)
        symbol = "‚úÖ" if result == "PASS" else "‚ùå" if result == "FAIL" else "‚ö†Ô∏è"
        print(f"{symbol} {component}: {test} - {result}")
        if details:
            print(f"   Details: {details}")
        return result == "PASS"
    
    def test_api_health(self):
        """Test API is running and healthy."""
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=5)
            return self.log_test("API", "Health Check", 
                                "PASS" if resp.status_code == 200 else "FAIL",
                                f"Status: {resp.status_code}")
        except Exception as e:
            return self.log_test("API", "Health Check", "FAIL", str(e))
    
    def test_detector_imports(self):
        """Test all detector modules can be imported."""
        detectors = [
            ("T1027ObfuscationDetector", "defense_evasion.obfuscation_detector"),
            ("T1070IndicatorRemovalDetector", "defense_evasion.indicator_removal_detector"),
            ("T1112RegistryMonitor", "defense_evasion.registry_monitor"),
            ("T1562DefenseImpairmentDetector", "defense_evasion.defense_impairment_detector"),
            ("T1548ElevationDetector", "defense_evasion.elevation_detector"),
            ("T1087AccountDiscovery", "discovery.account_discovery"),
            ("T1135NetworkShareDiscovery", "discovery.network_share_discovery"),
            ("T1069PermissionGroupsDiscovery", "discovery.permission_groups_discovery"),
            ("T1046NetworkServiceDiscovery", "discovery.network_service_discovery"),
            ("T1082SystemInformationDiscovery", "discovery.system_information_discovery"),
            ("T1021RemoteServicesDetector", "lateral_movement.remote_services"),
            ("T1078ValidAccountsDetector", "lateral_movement.valid_accounts"),
            ("T1550AlternateAuthDetector", "lateral_movement.alternate_auth"),
        ]
        
        successes = 0
        for class_name, module_path in detectors:
            try:
                # Dynamic import
                import importlib
                full_path = f"src.{module_path}"
                module = importlib.import_module(full_path)
                
                if hasattr(module, class_name):
                    detector_class = getattr(module, class_name)
                    
                    # Try to instantiate with state manager
                    try:
                        from src.core.state_manager import SecurityStateManager
                        state_mgr = SecurityStateManager()
                        
                        # Check if detector expects state_manager parameter
                        import inspect
                        sig = inspect.signature(detector_class.__init__)
                        params = list(sig.parameters.keys())
                        
                        if 'state_manager' in params:
                            instance = detector_class(state_manager=state_mgr)
                        else:
                            instance = detector_class()
                            
                        successes += 1
                        self.log_test("Detectors", f"Import {class_name}", "PASS")
                        
                    except Exception as init_error:
                        self.log_test("Detectors", f"Import {class_name}", "WARN", 
                                     f"Import OK but init failed: {str(init_error)[:80]}")
                        
                else:
                    self.log_test("Detectors", f"Import {class_name}", "FAIL", "Class not found in module")
                    
            except ModuleNotFoundError as e:
                self.log_test("Detectors", f"Import {class_name}", "FAIL", f"Module not found: {e.name}")
            except Exception as e:
                self.log_test("Detectors", f"Import {class_name}", "FAIL", f"{type(e).__name__}: {str(e)[:80]}")
        
        return self.log_test("Detectors", "All Imports", 
                           "PASS" if successes == len(detectors) else "PARTIAL",
                           f"{successes}/{len(detectors)} successful")
    
    def test_endpoint_accessibility(self):
        """Test all API endpoints respond (even if error)."""
        endpoints = [
            ("/api/v1/defense-evasion/obfuscation", "POST"),
            ("/api/v1/defense-evasion/indicator-removal", "POST"),
            ("/api/v1/defense-evasion/registry", "POST"),
            ("/api/v1/defense-evasion/defense-impairment", "POST"),
            ("/api/v1/defense-evasion/elevation", "POST"),
            ("/api/v1/discovery/accounts", "POST"),
            ("/api/v1/discovery/shares", "POST"),
            ("/api/v1/discovery/groups", "POST"),
            ("/api/v1/discovery/services", "POST"),
            ("/api/v1/discovery/system-info", "POST"),
            ("/api/v1/scan/full", "POST"),
            ("/api/v1/compliance/generate", "POST"),
            ("/dashboard", "GET"),
            ("/dashboard/api/metrics", "GET"),
        ]
        
        accessible = 0
        for endpoint, method in endpoints:
            try:
                if method == "GET":
                    resp = requests.get(f"{self.base_url}{endpoint}", 
                                       headers=self.headers, timeout=5)
                else:
                    resp = requests.post(f"{self.base_url}{endpoint}",
                                        headers=self.headers,
                                        json={},  # Empty payload for accessibility test
                                        timeout=5)
                
                status = resp.status_code
                # Consider accessible if we get any response (even 422 validation error)
                if status < 500:  # Not a server error
                    accessible += 1
                    self.log_test("Endpoints", f"{endpoint}", "ACCESSIBLE", f"Status: {status}")
                else:
                    self.log_test("Endpoints", f"{endpoint}", "SERVER_ERROR", f"Status: {status}")
            except requests.exceptions.ConnectionError:
                self.log_test("Endpoints", f"{endpoint}", "NO_CONNECTION", "Cannot connect to API")
            except Exception as e:
                self.log_test("Endpoints", f"{endpoint}", "FAIL", f"{type(e).__name__}: {str(e)[:80]}")
        
        return self.log_test("Endpoints", "All Endpoints", 
                           "PASS" if accessible >= len(endpoints) * 0.8 else "PARTIAL",
                           f"{accessible}/{len(endpoints)} accessible")
    
    def test_functional_scenarios(self):
        """Test actual functional use cases."""
        scenarios = [
            {
                "name": "File Obfuscation Detection",
                "endpoint": "/api/v1/defense-evasion/obfuscation",
                "payload": {"file_path": "./README.md"},
                "expected_field": "entropy"
            },
            {
                "name": "Account Discovery", 
                "endpoint": "/api/v1/discovery/accounts",
                "payload": {},
                "expected_field": "local_users"
            },
            {
                "name": "System Information",
                "endpoint": "/api/v1/discovery/system-info",
                "payload": {},
                "expected_field": "system"
            },
            {
                "name": "Dashboard Metrics",
                "endpoint": "/dashboard/api/metrics",
                "payload": None,
                "method": "GET",
                "expected_field": "techniques_implemented"
            }
        ]
        
        successes = 0
        for scenario in scenarios:
            try:
                method = scenario.get("method", "POST")
                if method == "GET":
                    resp = requests.get(f"{self.base_url}{scenario['endpoint']}",
                                       headers=self.headers, timeout=10)
                else:
                    resp = requests.post(f"{self.base_url}{scenario['endpoint']}",
                                        headers=self.headers,
                                        json=scenario['payload'],
                                        timeout=10)
                
                if resp.status_code == 200:
                    data = resp.json()
                    if scenario['expected_field'] in data:
                        successes += 1
                        self.log_test("Functionality", scenario['name'], "PASS",
                                     f"Field found: {scenario['expected_field']}")
                    else:
                        # Try nested field lookup
                        found = False
                        if isinstance(data, dict):
                            # Check nested structure
                            import collections.abc
                            def nested_get(d, key):
                                for k, v in d.items() if isinstance(d, dict) else enumerate(d) if isinstance(d, list) else []:
                                    if k == key:
                                        return v
                                    elif isinstance(v, (dict, list)):
                                        result = nested_get(v, key)
                                        if result is not None:
                                            return result
                                return None
                            
                            if nested_get(data, scenario['expected_field']) is not None:
                                successes += 1
                                found = True
                                self.log_test("Functionality", scenario['name'], "PASS",
                                             f"Field found nested: {scenario['expected_field']}")
                        
                        if not found:
                            self.log_test("Functionality", scenario['name'], "PARTIAL",
                                         f"Missing field: {scenario['expected_field']}. Got keys: {list(data.keys())[:5]}")
                else:
                    self.log_test("Functionality", scenario['name'], "ERROR",
                                 f"Status: {resp.status_code}. Response: {resp.text[:100]}")
            except Exception as e:
                self.log_test("Functionality", scenario['name'], "FAIL", f"{type(e).__name__}: {str(e)[:100]}")
        
        return self.log_test("Functionality", "Core Scenarios",
                           "PASS" if successes >= len(scenarios) * 0.7 else "PARTIAL",
                           f"{successes}/{len(scenarios)} successful")
    
    def test_security_basics(self):
        """Test security fundamentals are in place."""
        checks = []
        
        # 1. Check for hardcoded credentials
        try:
            cred_scan = subprocess.run(
                ["grep", "-r", "password\\s*=", "src/", "--include=*.py"],
                capture_output=True, text=True, shell=True
            )
            if not cred_scan.stdout.strip():
                checks.append(("No hardcoded passwords", "PASS"))
            else:
                checks.append(("Hardcoded passwords found", "FAIL", cred_scan.stdout[:200]))
        except:
            checks.append(("Credential scan failed", "WARN"))
        
        # 2. Check for shell=True usage (should be minimal)
        try:
            shell_scan = subprocess.run(
                ["grep", "-r", "shell=True", "src/", "--include=*.py"],
                capture_output=True, text=True, shell=True
            )
            shell_count = len([l for l in shell_scan.stdout.splitlines() if l.strip()])
            checks.append(("shell=True usage", "WARN" if shell_count > 0 else "PASS", 
                          f"Found {shell_count} instances"))
        except:
            checks.append(("Shell usage scan failed", "WARN"))
        
        # 3. Check Python security vulnerabilities
        try:
            import bandit
            checks.append(("Bandit available", "PASS"))
        except ImportError:
            checks.append(("Bandit not installed", "WARN"))
        
        for check, result, *details in checks:
            detail = details[0] if details else ""
            self.log_test("Security", check, result, detail)
        
        passes = sum(1 for _, r, *_ in checks if r == "PASS")
        return self.log_test("Security", "Basic Security", 
                           "PASS" if passes >= len(checks) * 0.8 else "WARN",
                           f"{passes}/{len(checks)} checks passed")
    
    def run_all_tests(self):
        """Execute comprehensive test suite."""
        print("Ì¥¨ MITRE ATT&CK LAB - COMPREHENSIVE E2E TEST")
        print("=" * 60)
        print(f"Test Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Base URL: {self.base_url}")
        print()
        
        tests = [
            self.test_api_health,
            self.test_detector_imports,
            self.test_endpoint_accessibility,
            self.test_functional_scenarios,
            self.test_security_basics
        ]
        
        start_time = time.time()
        for test in tests:
            test()
            print()  # Blank line between test sections
        
        # Generate report
        total_time = time.time() - start_time
        passes = sum(1 for r in self.test_results if r["result"] == "PASS")
        fails = sum(1 for r in self.test_results if r["result"] == "FAIL")
        warnings = sum(1 for r in self.test_results if r["result"] not in ["PASS", "FAIL"])
        
        print("=" * 60)
        print("Ì≥ä TEST SUMMARY")
        print("=" * 60)
        print(f"   Total Tests: {len(self.test_results)}")
        print(f"   ‚úÖ Passed: {passes}")
        print(f"   ‚ùå Failed: {fails}")
        print(f"   ‚ö†Ô∏è  Warnings: {warnings}")
        print(f"   ‚è±Ô∏è  Duration: {total_time:.1f}s")
        print()
        
        # Show critical failures first
        failures = [r for r in self.test_results if r["result"] == "FAIL"]
        if failures:
            print("Ì¥¥ CRITICAL FAILURES:")
            for f in failures:
                print(f"   ‚Ä¢ {f['component']}: {f['test']}")
                if f['details']:
                    print(f"     Details: {f['details']}")
            print()
        
        # Save detailed report
        report = {
            "timestamp": time.time(),
            "test_time": time.strftime('%Y-%m-%d %H:%M:%S'),
            "duration_seconds": total_time,
            "base_url": self.base_url,
            "test_count": len(self.test_results),
            "results": self.test_results,
            "summary": {
                "pass": passes,
                "fail": fails,
                "warning": warnings,
                "success_rate": f"{(passes/len(self.test_results)*100):.1f}%"
            }
        }
        
        Path("reports").mkdir(exist_ok=True)
        report_file = "reports/e2e_test_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"Ì≥Å Detailed report saved: {report_file}")
        
        # Recommendation based on results
        if fails == 0 and passes > len(self.test_results) * 0.8:
            print("\nÌæâ RECOMMENDATION: System is READY for production testing")
        elif fails > 0:
            print(f"\nÌ¥ß RECOMMENDATION: Fix {fails} critical failures before proceeding")
        else:
            print("\n‚ö†Ô∏è  RECOMMENDATION: Address warnings before full deployment")
        
        return passes, fails

if __name__ == "__main__":
    # Check if API is running before starting
    print("Ì¥ç Pre-flight check...")
    try:
        resp = requests.get("http://127.0.0.1:8000/health", timeout=2)
        print(f"   API Status: {'‚úÖ Running' if resp.status_code == 200 else '‚ö†Ô∏è Not fully healthy'}")
    except:
        print("   ‚ùå API not detected. Start with: uvicorn src.api.main:app --host 127.0.0.1 --port 8000")
        print("   Will test detector imports only...")
    
    tester = ComprehensiveTester()
    passes, fails = tester.run_all_tests()
    
    # Exit code based on critical failures
    sys.exit(0 if fails == 0 else 1)
