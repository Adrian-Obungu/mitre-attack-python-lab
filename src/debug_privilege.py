#!/usr/bin/env python3
"""Debug the privilege auditor module"""

import sys
import traceback

sys.path.insert(0, 'src')

print("Debugging Privilege Auditor...")
print("=" * 60)

try:
    print("1. Testing imports...")
    from privilege.privilege_auditor import PrivilegeAuditor
    print("   ✓ PrivilegeAuditor imported")
    
    print("\n2. Creating instance...")
    auditor = PrivilegeAuditor()
    print("   ✓ Instance created")
    
    print("\n3. Checking available methods...")
    methods = [m for m in dir(auditor) if not m.startswith('_')]
    print(f"   Available methods: {', '.join(methods[:10])}...")
    
    print("\n4. Trying to run scan...")
    try:
        results = auditor.scan()
        print(f"   ✓ Scan completed. Found {len(results)} results")
        
        if results:
            print("\n   Sample results:")
            for i, result in enumerate(results[:3]):
                print(f"   {i+1}. Technique: {result.get('technique', 'N/A')}")
                print(f"      Description: {result.get('description', 'N/A')[:80]}...")
        else:
            print("   ⚠ Scan returned empty results")
            
    except Exception as e:
        print(f"   ✗ Scan failed: {e}")
        traceback.print_exc()
        
except ImportError as e:
    print(f"✗ Import failed: {e}")
    
    # Try to debug import path
    print("\nDebugging import path...")
    import os
    print(f"Current directory: {os.getcwd()}")
    print(f"src exists: {os.path.exists('src')}")
    print(f"privilege directory exists: {os.path.exists('src/privilege')}")
    
    if os.path.exists('src/privilege'):
        print("Contents of src/privilege:")
        for f in os.listdir('src/privilege'):
            print(f"  - {f}")
except Exception as e:
    print(f"✗ Unexpected error: {e}")
    traceback.print_exc()

print("\n" + "=" * 60)
print("Debug complete")
