import os
import subprocess
import sys
import json
import time
import requests

def get_python_executable():
    """Dynamically determine the absolute path to the Python executable from the virtual environment."""
    base_path = os.path.dirname(os.path.abspath(__file__))
    if sys.platform == "win32":
        return os.path.join(base_path, "venv", "Scripts", "python.exe")
    else:
        return os.path.join(base_path, "venv", "bin", "python")

PYTHON_EXECUTABLE = get_python_executable()

def run_command(cmd_parts, check=True):
    """Run shell command and return output"""
    print(f"\n>>> Running: {' '.join(cmd_parts)}")
    try:
        result = subprocess.run(
            cmd_parts, 
            capture_output=True, 
            text=True,
            check=check
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr

def _test_module_helper(module_name, args=""):
    """Test a specific module"""
    print(f"\n{'='*60}")
    print(f"Testing: {module_name}")
    print('='*60)
    
    cmd_parts = [PYTHON_EXECUTABLE, module_name]
    if args:
        cmd_parts.append(args)

    returncode, stdout, stderr = run_command(cmd_parts, check=False)
    
    if returncode == 0:
        print(f"✓ {module_name} ran successfully")
        if stdout:
            print(f"Output (first 500 chars):\n{stdout[:500]}...")
    else:
        print(f"✗ {module_name} failed with code {returncode}")
        if stderr:
            print(f"Error:\n{stderr[:500]}")
    
    return returncode == 0

def test_api_endpoint():
    """Test the API privilege endpoint"""
    print(f"\n{'='*60}")
    print("Testing API Endpoint")
    print('='*60)
    
    # Start API server in background
    api_cmd_parts = [PYTHON_EXECUTABLE, "-m", "uvicorn", "src.api.main:app", "--port", "8000"]
    api_process = subprocess.Popen(
        api_cmd_parts,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Give server time to start
    time.sleep(10)
    
    # Test health endpoint using requests
    health_url = "http://localhost:8000/health"
    try:
        response = requests.get(health_url, timeout=5)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        health_data = response.json()
        if health_data.get("status") == "healthy":
            print("✓ Health endpoint working")
            
            # Test privilege endpoint
            privilege_url = "http://localhost:8000/privilege/scan"
            try:
                response = requests.get(privilege_url, headers={"X-API-Key": "dev-key-123"}, timeout=20)
                response.raise_for_status()
                priv_data = response.json()
                print("✓ Privilege endpoint accessible")
                print(f"  Returned {len(priv_data.get('findings', []))} detection(s)")
                if priv_data.get('findings'):
                    for i, detection in enumerate(priv_data['findings'][:3]):  # Show first 3
                        print(f"  Detection {i+1}: {detection.get('technique_name', 'Unknown')}")
                return True # API test successful
            except requests.exceptions.RequestException as e:
                print(f"✗ Privilege endpoint failed: {e}")
                return False
        else:
            print(f"✗ Health endpoint returned unhealthy status: {health_data}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"✗ Health endpoint failed to connect: {e}")
        # Print stderr and stdout from the API process for debugging
        if api_process.poll() is not None: # If process has terminated
            stdout_data, stderr_data = api_process.communicate()
            if stdout_data:
                print(f"--- API Server STDOUT ---\n{stdout_data[:500]}...")
            if stderr_data:
                print(f"--- API Server STDERR ---\n{stderr_data[:500]}...")
        else:
            print("--- API Server is still running, check its logs manually ---")
        return False
    finally:
        # Kill API server
        api_process.terminate()
        api_process.wait()

def main():
    print("MITRE ATT&CK Python Lab - Chapter 5 E2E Test")
    print("=" * 60)
    
    # Check environment
    print("\n1. Environment Check")
    print("-" * 40)
    
    # Python version
    py_code, py_out, py_err = run_command([PYTHON_EXECUTABLE, "--version"])
    print(f"Python: {py_out.strip() if py_code == 0 else 'Not found'}")
    
    # Check src directory
    if os.path.exists("src"):
        print("✓ src directory exists")
        src_files = os.listdir("src")
        print(f"  Contains: {', '.join(src_files[:5])}...")
    else:
        print("✗ src directory missing!")
        return False
    
    # Test modules
    print("\n2. Module Tests")
    print("-" * 40)
    
    modules = [
        ("src/privilege/privilege_auditor.py", "--help"),
        ("src/privilege/path_hijack_detector.py", ""),
        ("src/privilege/service_scanner.py", ""),
        ("src/privilege/logon_script_detector.py", ""),
    ]
    
    success_count = 0
    for module, args in modules:
        if _test_module_helper(module, args):
            success_count += 1
    
    # Test API
    print("\n3. API Integration Test")
    print("-" * 40)
    api_success = test_api_endpoint()
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print('='*60)
    print(f"Modules tested: {len(modules)}")
    print(f"Modules passed: {success_count}/{len(modules)}")
    print(f"API test: {'PASS' if api_success else 'FAIL'}")
    
    if success_count == len(modules) and api_success:
        print("\n✅ All Chapter 5 features appear functional!")
        return True
    else:
        print("\n❌ Some issues detected. Needs investigation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
