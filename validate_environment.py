#!/usr/bin/env python3
"""
Comprehensive environment validation for MITRE ATT&CK Lab
"""
import sys
import subprocess
import os
from typing import List

def run_command(command_args: List[str], check: bool = True):
    """Run command and return result"""
    try:
        # Determine the correct Python executable for the virtual environment
        VENV_PYTHON = sys.executable

        # If the first argument is a Python script, ensure it's executed with the current venv Python
        if command_args and command_args[0].endswith(".py"):
            processed_command_args = [VENV_PYTHON] + command_args
        # If the command itself is 'python', replace it with VENV_PYTHON for consistency
        elif command_args and command_args[0] == "python":
            processed_command_args = [VENV_PYTHON] + command_args[1:]
        else:
            processed_command_args = command_args

        result = subprocess.run(processed_command_args, capture_output=True, text=True, check=check)
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr
    except Exception as e:
        return 1, "", str(e)

def check_python_environment():
    """Check Python environment"""
    print("=== PYTHON ENVIRONMENT ===")
    
    # Check Python version
    code, out, err = run_command(["python", "--version"])
    print(f"Python Version: {out.strip() if code == 0 else 'ERROR'}")
    
    # Check core imports
    test_imports = [
        "import fastapi",
        "import uvicorn", 
        "import dnslib",
        "import prometheus_client",
        "import requests",
        "import rich"
    ]
    
    print("\n=== CORE IMPORTS ===")
    for imp in test_imports:
        code, out, err = run_command(["python", "-c", f"{imp}; print(\"✅ {imp.split()[1]}\")"])
        if code == 0:
            print(out.strip())
        else:
            print(f"❌ {imp.split()[1]}: {err}")

def check_core_modules():
    """Check core modules functionality"""
    print("\n=== CORE MODULE FUNCTIONALITY ===")
    
    # Test TCP scanner
    print("Testing TCP Scanner...")
    code, out, err = run_command(["src/reconnaissance/tcp_connect_scan.py", "scanme.nmap.org", "-p", "80", "--timeout", "2"])
    if code == 0 and "Open" in out:
        print("✅ TCP Scanner: Functional")
    else:
        print(f"❌ TCP Scanner: {err[:100]}...")
    
    # Test DNS recon (basic import)
    print("\nTesting DNS Recon...")
    code, out, err = run_command('venv/Scripts/python -c "from src.reconnaissance.dns_recon import main; print(\"✅ DNS Recon imports OK\")"')
    if code == 0:
        print(out.strip())
    else:
        print(f"❌ DNS Recon: {err[:100]}...")
    
    # Test Persistence Auditor
    print("\nTesting Persistence Auditor...")
    code, out, err = run_command('venv/Scripts/python src/persistence/persistence_auditor.py --help')
    if code == 0:
        print("✅ Persistence Auditor: Functional")
    else:
        print(f"❌ Persistence Auditor: {err[:100]}...")

def check_api_server():
    """Check API server functionality"""
    print("\n=== API SERVER ===")
    
    # Start API server
    print("Starting API server...")
    api_proc = subprocess.Popen(
        ["venv/Scripts/python", "-m", "uvicorn", "src.api_server:app", "--host", "127.0.0.1", "--port", "8081"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    import time
    time.sleep(3)
    
    # Test health endpoint
    print("Testing API health...")
    code, out, err = run_command('curl -s -H "X-API-Key: test-key-123" http://localhost:8081/health')
    if code == 0 and '"status":"healthy"' in out:
        print("✅ API Health: Functional")
    else:
        print(f"❌ API Health: {out[:100] if out else err[:100]}")
    
    # Kill API server
    api_proc.terminate()
    api_proc.wait()

def main():
    """Main validation routine"""
    print("MITRE ATT&CK LAB - ENVIRONMENT VALIDATION")
    print("=" * 50)
    
    check_python_environment()
    check_core_modules()
    check_api_server()
    
    print("\n" + "=" * 50)
    print("VALIDATION COMPLETE")
    print("=" * 50)

if __name__ == "__main__":
    main()
