#!/usr/bin/env python3
"""Test all module imports to ensure no broken dependencies"""

import sys
print(f"Python version: {sys.version}")

modules_to_test = [
    "src.reconnaissance.dns_recon",
    "src.reconnaissance.tcp_connect_scan",
    "src.persistence.persistence_auditor",
    "src.privilege.privilege_auditor",
    "src.privilege.path_hijack_detector",
    "src.privilege.service_scanner",
    "src.privilege.logon_script_detector",
    "src.api.main",
    "src.utils.logging_config",
]

print("\nTesting imports...")
for module_path in modules_to_test:
    try:
        __import__(module_path)
        print(f"✓ {module_path}")
    except ImportError as e:
        print(f"✗ {module_path}: {e}")
    except Exception as e:
        print(f"⚠ {module_path}: {e}")

print("\nChecking key class availability...")
try:
    from src.privilege.privilege_auditor import PrivilegeAuditor
    print("✓ PrivilegeAuditor class available")
except ImportError as e:
    print(f"✗ PrivilegeAuditor: {e}")

try:
    from src.api.main import app
    print("✓ FastAPI app available")
except ImportError as e:
    print(f"✗ FastAPI app: {e}")

print("\nImport test complete!")
