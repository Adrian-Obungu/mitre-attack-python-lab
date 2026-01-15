#!/usr/bin/env python3
"""Final comprehensive test of Chapter 5 implementation"""

import sys
import subprocess
import time
import psutil

def kill_uvicorn():
    """Kill any running uvicorn processes for the test API server."""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'uvicorn' in proc.info['name'] and 'main:app' in ' '.join(proc.info['cmdline']):
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def run_test(name, command, cwd=None):
    """Run a test command"""
    print(f"\n{'='*60}")
    print(f"Test: {name}")
    print('='*60)
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=cwd
        )
        
        if result.returncode == 0:
            print(f"✓ {name} - PASSED")
            return True
        else:
            print(f"✗ {name} - FAILED (code: {result.returncode})")
            if result.stderr:
                print(f"Error:\n{result.stderr[:500]}")
            return False
    except subprocess.TimeoutExpired:
        print(f"✗ {name} - TIMEOUT")
        return False
    except Exception as e:
        print(f"✗ {name} - ERROR: {e}")
        return False

def main():
    print("Chapter 5 - Final Comprehensive Test")
    print("=" * 60)
    
    tests = [
        {"name": "Module Import", "command": ["venv/Scripts/python", "-c", "import sys; sys.path.insert(0, 'src'); from privilege.privilege_auditor import PrivilegeAuditor; print('Import OK')"]},
        {"name": "Privilege Auditor Help", "command": ["venv/Scripts/python", "src/privilege/privilege_auditor.py", "--help"]},
        {"name": "Quick Scan Test", "command": ["venv/Scripts/python", "src/privilege/privilege_auditor.py", "--quick-scan"]},
        {"name": "API Server Start", "command": ["venv/Scripts/uvicorn", "main:app", "--reload", "--port", "8000"], "cwd": "src"},
        {"name": "API Health Check", "command": ["venv/Scripts/python", "-c", "import requests; response = requests.get('http://localhost:8000/health', timeout=5); response.raise_for_status(); assert 'healthy' in response.text; print('API Healthy')"]},
    ]
    
    # Kill any existing API server
    kill_uvicorn()
    time.sleep(1) # Give a moment for the port to be freed
    
    passed = 0
    for test in tests:
        if run_test(test["name"], test["command"], cwd=test.get("cwd")):
            passed += 1
            if test["name"] == "API Server Start":
                time.sleep(3) # Give the server a moment to start up

    # Clean up
    kill_uvicorn()
    
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print('='*60)
    print(f"Passed: {passed}/{len(tests)}")
    
    if passed == len(tests):
        print("\n✅ CHAPTER 5 IMPLEMENTATION IS STABLE AND READY!")
        return True
    else:
        print(f"\n⚠ {len(tests) - passed} tests failed. Needs attention before Chapter 6.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
