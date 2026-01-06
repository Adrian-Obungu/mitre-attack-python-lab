#!/usr/bin/env python3
"""
Comprehensive environment validation for MITRE ATT&CK Lab - Windows Fixed
"""
import sys
import subprocess
import os

# Get absolute path to venv python
VENV_PYTHON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv", "Scripts", "python.exe")

def run_command(cmd):
    """Run command and return result"""
    try:
        # Use absolute path for python
        cmd = cmd.replace("venv/Scripts/python", f'"{VENV_PYTHON}"')
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)

def check_python_environment():
    """Check Python environment"""
    print("=== PYTHON ENVIRONMENT ===")
    
    # Check Python version using absolute path
    code, out, err = run_command(f'"{VENV_PYTHON}" --version')
    print(f"Python Version: {out.strip() if code == 0 else 'ERROR: ' + err}")
    
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
        code, out, err = run_command(f'"{VENV_PYTHON}" -c "{imp}; print(\"✅ {imp.split()[1]}\")"')
        if code == 0:
            print(out.strip())
        else:
            print(f"❌ {imp.split()[1]}: {err[:100]}")

def check_core_modules():
    """Check core modules functionality"""
    print("\n=== CORE MODULE FUNCTIONALITY ===")
    
    # Test TCP scanner
    print("Testing TCP Scanner...")
    code, out, err = run_command(f'"{VENV_PYTHON}" src/reconnaissance/tcp_connect_scan.py scanme.nmap.org -p 80 --timeout 2')
    if code == 0 and "Open" in out:
        print("✅ TCP Scanner: Functional")
    else:
        print(f"❌ TCP Scanner: {err[:100] if err else out[:100]}")
    
    # Test DNS recon
    print("\nTesting DNS Recon...")
    # First check wordlist exists
    if os.path.exists("config/common_subdomains.txt"):
        code, out, err = run_command(f'"{VENV_PYTHON}" src/reconnaissance/dns_recon.py -d github.com -w config/common_subdomains.txt -t 1 --timeout 2')
        if code == 0:
            print("✅ DNS Recon: Functional")
        else:
            print(f"❌ DNS Recon: {err[:100] if err else 'Unknown error'}")
    else:
        print("⚠️ DNS Recon: Wordlist missing, skipping test")
    
    # Test Persistence Auditor
    print("\nTesting Persistence Auditor...")
    code, out, err = run_command(f'"{VENV_PYTHON}" src/persistence/persistence_auditor.py --help')
    if code == 0:
        print("✅ Persistence Auditor: Functional")
    else:
        print(f"❌ Persistence Auditor: {err[:100] if err else out[:100]}")

def check_api_server():
    """Check API server functionality"""
    print("\n=== API SERVER ===")
    
    # Start API server
    print("Starting API server...")
    api_proc = subprocess.Popen(
        [VENV_PYTHON, "-m", "uvicorn", "src.api_server:app", "--host", "127.0.0.1", "--port", "8082"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    import time
    time.sleep(3)
    
    # Test health endpoint
    print("Testing API health...")
    code, out, err = run_command('curl -s -H "X-API-Key: test-key-123" http://localhost:8082/health')
    if code == 0 and '"status":"healthy"' in out:
        print("✅ API Health: Functional")
    else:
        print(f"❌ API Health: {out[:100] if out else err[:100]}")
    
    # Test scanner endpoint
    print("Testing API scanner...")
    code, out, err = run_command('curl -s -H "X-API-Key: test-key-123" -H "Content-Type: application/json" -X POST http://localhost:8082/scan -d \'{"target":"scanme.nmap.org","ports":"80","scan_type":"connect"}\'')
    if code == 0 and '"status"' in out:
        print("✅ API Scanner: Functional")
    else:
        print(f"❌ API Scanner: {out[:100] if out else err[:100]}")
    
    # Kill API server
    api_proc.terminate()
    api_proc.wait()

def main():
    """Main validation routine"""
    print("MITRE ATT&CK LAB - ENVIRONMENT VALIDATION (WINDOWS FIXED)")
    print("=" * 60)
    print(f"Using Python: {VENV_PYTHON}")
    
    check_python_environment()
    check_core_modules()
    check_api_server()
    
    print("\n" + "=" * 60)
    print("VALIDATION COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()
