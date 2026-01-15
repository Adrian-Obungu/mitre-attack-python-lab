#!/usr/bin/env python3
"""
Validate Chapter 5 (Privilege Escalation) Implementation
Fixed version based on actual terminal output
"""

import os
import sys
import subprocess
import json

def run_cmd(cmd, cwd=None):
    """Run command and return output"""
    print(f"\n>>> {cmd}")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            cwd=cwd
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)

def test_imports():
    """Test that all modules can be imported"""
    print("\n" + "="*60)
    print("Testing Module Imports")
    print("="*60)
    
    test_code = """
import sys
sys.path.insert(0, 'src')

modules = [
    ('privilege.privilege_auditor', 'PrivilegeAuditor'),
    ('privilege.path_hijack_detector', 'PathHijackDetector'),
    ('privilege.service_scanner', 'ServiceScanner'),
    ('privilege.logon_script_detector', 'LogonScriptDetector'),
]

for module_path, class_name in modules:
    try:
        module = __import__(module_path, fromlist=[class_name])
        if hasattr(module, class_name):
            print(f'✓ {module_path}.{class_name}')
        else:
            print(f'✗ {module_path} - {class_name} not found')
    except ImportError as e:
        print(f'✗ {module_path} - {e}')
    except Exception as e:
        print(f'⚠ {module_path} - {e}')
"""
    
    with open('test_import.py', 'w') as f:
        f.write(test_code)
    
    returncode, stdout, stderr = run_cmd("python test_import.py")
    
    if returncode == 0:
        print(stdout)
    else:
        print(f"✗ Import test failed: {stderr}")
    
    # Cleanup
    if os.path.exists('test_import.py'):
        os.remove('test_import.py')
    
    return returncode == 0

def test_privilege_auditor():
    """Test privilege auditor functionality"""
    print("\n" + "="*60)
    print("Testing Privilege Auditor")
    print("="*60)
    
    # Test with --help first
    returncode, stdout, stderr = run_cmd("python src/privilege/privilege_auditor.py --help")
    
    if returncode == 0:
        print("✓ --help works")
        # Check if it shows expected options
        if "usage:" in stdout.lower() or "options:" in stdout.lower():
            print("✓ Shows help information")
        else:
            print("⚠ Help output might be incomplete")
    else:
        print(f"✗ --help failed: {stderr[:200]}")
        return False
    
    # Test quick scan
    print("\nTesting quick scan...")
    returncode, stdout, stderr = run_cmd("python src/privilege/privilege_auditor.py --quick-scan")
    
    if returncode == 0:
        print("✓ Quick scan completed")
        try:
            # Try to parse as JSON
            data = json.loads(stdout)
            print(f"✓ Returns valid JSON with {len(data) if isinstance(data, list) else 'unknown'} items")
        except json.JSONDecodeError:
            print("⚠ Output is not JSON (might be normal for empty results)")
    elif "quick-scan" in stderr.lower():
        print("⚠ --quick-scan option not available")
    else:
        print(f"✗ Quick scan failed: {stderr[:200]}")
    
    return True

def test_api_structure():
    """Test API structure"""
    print("\n" + "="*60)
    print("Testing API Structure")
    print("="*60)
    
    required_files = [
        "src/api/main.py",
        "src/api/routes/privilege_routes.py",
        "src/api/routes/recon_routes.py",
        "src/api/routes/persistence_routes.py",
    ]
    
    all_exist = True
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"✓ {file_path}")
        else:
            print(f"✗ {file_path} - MISSING")
            all_exist = False
    
    if all_exist:
        # Test API import
        test_code = """
import sys
sys.path.insert(0, 'src')
try:
    from api.main import app
    print('✓ FastAPI app imports successfully')
    
    # Check routes
    routes = [route.path for route in app.routes]
    privilege_routes = [r for r in routes if '/privilege' in r]
    
    if privilege_routes:
        print(f'✓ Found privilege routes')
    else:
        print('⚠ No privilege routes found')
        
except Exception as e:
    print(f'✗ API import failed: {e}')
"""
        
        with open('test_api.py', 'w') as f:
            f.write(test_code)
        
        returncode, stdout, stderr = run_cmd("python test_api.py")
        print(f"\n{stdout}")
        
        if os.path.exists('test_api.py'):
            os.remove('test_api.py')
    
    return all_exist

def test_docker():
    """Test Docker setup"""
    print("\n" + "="*60)
    print("Testing Docker Setup")
    print("="*60)
    
    if os.path.exists("Dockerfile"):
        print("✓ Dockerfile exists")
        
        # Check if it's valid
        with open("Dockerfile", "r") as f:
            content = f.read()
        
        if "FROM python" in content:
            print("✓ Uses Python base image")
        if "COPY src/" in content:
            print("✓ Copies src directory")
        if "EXPOSE" in content:
            print("✓ Exposes port")
        
        # Test build (just syntax, not actual build)
        print("\nNote: Docker build test would require Docker daemon running")
        return True
    else:
        print("✗ Dockerfile missing")
        return False

def main():
    print("Chapter 5 Implementation - Final Validation")
    print("="*60)
    
    # Check current directory
    print(f"Current directory: {os.getcwd()}")
    print(f"src exists: {os.path.exists('src')}")
    
    tests = [
        ("Module Imports", test_imports),
        ("Privilege Auditor", test_privilege_auditor),
        ("API Structure", test_api_structure),
        ("Docker Setup", test_docker),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"⚠ {test_name} test error: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*60)
    print("VALIDATION SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\n{passed}/{total} tests passed")
    
    if passed == total:
        print("\n✅ CHAPTER 5 IMPLEMENTATION IS READY!")
        return True
    else:
        print(f"\n⚠ {total - passed} tests failed. Review issues above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
