#!/usr/bin/env python3
"""Check if PrivilegeAuditor has scan method"""

import sys
sys.path.insert(0, 'src')

try:
    from privilege.privilege_auditor import PrivilegeAuditor
    print("✓ PrivilegeAuditor imported")
    
    auditor = PrivilegeAuditor()
    print("✓ Instance created")
    
    # Check available methods
    methods = [m for m in dir(auditor) if not m.startswith('_')]
    print(f"Available methods: {', '.join(methods)}")
    
    if 'scan' in methods:
        print("✓ scan method exists")
        # Try to call it
        try:
            results = auditor.scan()
            print(f"✓ scan() executed, returned {len(results) if results else 0} results")
        except Exception as e:
            print(f"✗ scan() failed: {e}")
    else:
        print("✗ scan method not found in PrivilegeAuditor")
        
        # Let's check the actual class definition
        import inspect
        source = inspect.getsource(PrivilegeAuditor)
        if 'def scan' in source:
            print("  But scan method is defined in source...")
        else:
            print("  scan method not defined in class")
            
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
