#!/usr/bin/env python3
"""Simple validation script for setup"""

import os
import sys

def check_files():
    """Check that essential files exist"""
    required_files = [
        'README.md',
        'src/reconnaissance/PortScan_Enhanced.py',
        'src/defense/HoneyResolver_Enhanced.py',
        'config/requirements.txt',
        '.gitignore'
    ]
    
    missing = []
    for file in required_files:
        if not os.path.exists(file):
            missing.append(file)
    
    return missing

def main():
    print("=== Project Setup Validation ===")
    
    # Check files
    missing = check_files()
    if missing:
        print("❌ Missing files:")
        for file in missing:
            print(f"   - {file}")
        return 1
    else:
        print("✅ All required files present")
    
    # Check Python imports
    print("\nTesting Python imports...")
    try:
        import scapy
        import dnslib
        print("✅ Core dependencies can be imported")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return 1
    
    print("\n✅ Validation passed!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
