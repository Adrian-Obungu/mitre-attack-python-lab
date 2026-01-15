#!/usr/bin/env python3
"""Test and fix API integration for Chapter 5"""

import os
import sys

def check_api_structure():
    """Check if API structure is complete"""
    print("Checking API structure...")
    issues = []
    
    # Check main API file
    if not os.path.exists("src/api/main.py"):
        issues.append("Missing src/api/main.py")
    else:
        with open("src/api/main.py", 'r') as f:
            content = f.read()
            if "privilege" not in content.lower():
                issues.append("main.py doesn't seem to include privilege routes")
    
    # Check privilege routes
    if not os.path.exists("src/api/privilege_routes.py"):
        issues.append("Missing src/api/privilege_routes.py")
    
    # Check if routes are registered
    if os.path.exists("src/api/main.py"):
        with open("src/api/main.py", 'r') as f:
            lines = f.readlines()
            privilege_route_import = False
            privilege_route_include = False
            
            for line in lines:
                if "privilege_routes" in line and "import" in line:
                    privilege_route_import = True
                if "privilege" in line and "include_router" in line:
                    privilege_route_include = True
            
            if not privilege_route_import:
                issues.append("main.py doesn't import privilege_routes")
            if not privilege_route_include:
                issues.append("main.py doesn't include privilege router")
    
    return issues

def create_missing_files():
    """Create missing API files"""
    print("\nCreating missing API files...")
    
    # Create privilege_routes.py if missing
    if not os.path.exists("src/api/privilege_routes.py"):
        privilege_routes_content = '''"""
Privilege Escalation API Routes
Provides endpoints for privilege escalation detection
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
import logging

from src.privilege.privilege_auditor import PrivilegeAuditor

router = APIRouter(
    prefix="/privilege",
    tags=["privilege"],
    responses={404: {"description": "Not found"}},
)

@router.get("/scan", response_model=List[Dict[str, Any]])
async def scan_for_privilege_escalation():
    """
    Scan for privilege escalation vectors
    
    Returns:
        List of privilege escalation detections with MITRE technique mappings
    """
    try:
        auditor = PrivilegeAuditor()
        results = auditor.scan()
        return results
    except Exception as e:
        logging.error(f"Privilege scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def privilege_health():
    """Health check for privilege escalation module"""
    return {"status": "healthy", "module": "privilege_escalation"}
'''
        
        os.makedirs("src/api", exist_ok=True)
        with open("src/api/privilege_routes.py", 'w') as f:
            f.write(privilege_routes_content)
        print("✓ Created src/api/privilege_routes.py")
    
    # Update main.py to include privilege routes
    if os.path.exists("src/api/main.py"):
        with open("src/api/main.py", 'r') as f:
            content = f.read()
        
        # Check if we need to add the import
        if "from .routes import privilege_routes" not in content:
            # Find where to add the import
            lines = content.split('\n')
            new_lines = []
            import_added = False
            
            for line in lines:
                new_lines.append(line)
                # Add after other route imports
                if "from .routes import" in line and not import_added:
                    new_lines.append("from .routes import privilege_routes")
                    import_added = True
            
            content = '\n'.join(new_lines)
        
        # Check if we need to include the router
        if "privilege_routes.router" not in content:
            # Find where to add the include_router
            lines = content.split('\n')
            new_lines = []
            router_added = False
            
            for line in lines:
                new_lines.append(line)
                # Add after other router includes
                if "include_router" in line and "recon_routes" in line and not router_added:
                    new_lines.append("app.include_router(privilege_routes.router)")
                    router_added = True
            
            content = '\n'.join(new_lines)
        
        with open("src/api/main.py", 'w') as f:
            f.write(content)
        
        print("✓ Updated src/api/main.py")
    
    # Check if routes directory exists
    if not os.path.exists("src/api/routes"):
        os.makedirs("src/api/routes", exist_ok=True)
        open("src/api/routes/__init__.py", 'w').close()
        print("✓ Created src/api/routes directory")
        
        # Move privilege_routes.py to routes directory
        if os.path.exists("src/api/privilege_routes.py"):
            os.rename("src/api/privilege_routes.py", "src/api/routes/privilege_routes.py")
            print("✓ Moved privilege_routes.py to routes directory")

def main():
    print("API Integration Test and Fix")
    print("=" * 60)
    
    # Check for issues
    issues = check_api_structure()
    
    if issues:
        print(f"Found {len(issues)} issues:")
        for issue in issues:
            print(f"  ✗ {issue}")
        
        # Fix issues
        create_missing_files()
        
        # Re-check
        print("\nRe-checking after fixes...")
        issues = check_api_structure()
        
        if issues:
            print(f"Still have {len(issues)} issues:")
            for issue in issues:
                print(f"  ✗ {issue}")
        else:
            print("✓ All API issues resolved!")
    else:
        print("✓ API structure looks good!")
    
    # Test API
    print("\nTesting API...")
    try:
        # Simple import test
        import sys
        sys.path.insert(0, 'src')
        
        from api.main import app
        print("✓ FastAPI app imports successfully")
        
        # Check routes
        routes = [route.path for route in app.routes]
        privilege_routes = [r for r in routes if '/privilege' in r]
        
        if privilege_routes:
            print(f"✓ Found privilege routes: {', '.join(privilege_routes)}")
        else:
            print("✗ No privilege routes found in FastAPI app")
            
    except Exception as e:
        print(f"✗ API test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
