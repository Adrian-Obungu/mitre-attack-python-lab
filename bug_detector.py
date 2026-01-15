#!/usr/bin/env python3
"""Detect and fix common issues in Chapter 5 implementation"""

import os
import sys
import ast
import re

def check_file_syntax(filepath):
    """Check Python file syntax"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            ast.parse(f.read())
        return True, "Syntax OK"
    except SyntaxError as e:
        return False, f"Syntax error: {e}"

def check_imports(filepath):
    """Check for import issues"""
    issues = []
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for relative imports that might fail
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        if line.strip().startswith('from .') or line.strip().startswith('from ..'):
            # Check if this might be problematic
            issues.append(f"Line {i}: Relative import - {line.strip()}")
    
    return issues

def check_missing_docstrings(filepath):
    """Check for missing docstrings in classes and functions"""
    issues = []
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    tree = ast.parse(content)
    
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            # Check class docstring
            if not ast.get_docstring(node):
                issues.append(f"Class '{node.name}' missing docstring")
        
        if isinstance(node, ast.FunctionDef):
            # Skip if it's a private method starting with _
            if not node.name.startswith('_'):
                if not ast.get_docstring(node):
                    issues.append(f"Function '{node.name}' missing docstring")
    
    return issues

def check_common_bugs(filepath):
    """Check for common bugs"""
    issues = []
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for bare except
    if 'except:' in content and 'except Exception:' not in content:
        issues.append("Bare 'except:' found - should use 'except Exception:'")
    
    # Check for print statements (should use logging)
    if 'print(' in content and 'logging' not in content:
        issues.append("print() statements found - consider using logging")
    
    # Check for hardcoded paths
    if 'C:\\' in content or '/home/' in content:
        issues.append("Hardcoded paths found - use config or environment variables")
    
    return issues

def analyze_module(module_path):
    """Analyze a module for issues"""
    print(f"\nAnalyzing: {module_path}")
    print("-" * 40)
    
    if not os.path.exists(module_path):
        print(f"✗ File does not exist: {module_path}")
        return False
    
    # Check syntax
    syntax_ok, syntax_msg = check_file_syntax(module_path)
    if syntax_ok:
        print(f"✓ {syntax_msg}")
    else:
        print(f"✗ {syntax_msg}")
        return False
    
    # Check imports
    import_issues = check_imports(module_path)
    if import_issues:
        print("⚠ Import issues found:")
        for issue in import_issues:
            print(f"  - {issue}")
    else:
        print("✓ No import issues found")
    
    # Check docstrings
    docstring_issues = check_missing_docstrings(module_path)
    if docstring_issues:
        print("⚠ Missing docstrings:")
        for issue in docstring_issues[:3]:  # Show first 3
            print(f"  - {issue}")
        if len(docstring_issues) > 3:
            print(f"  ... and {len(docstring_issues) - 3} more")
    else:
        print("✓ All docstrings present")
    
    # Check common bugs
    bug_issues = check_common_bugs(module_path)
    if bug_issues:
        print("⚠ Common bugs/issues:")
        for issue in bug_issues:
            print(f"  - {issue}")
    else:
        print("✓ No common bugs found")
    
    return True

def main():
    print("Chapter 5 Implementation - Bug Detection Scan")
    print("=" * 60)
    
    # Define modules to check
    modules = [
        "src/privilege/privilege_auditor.py",
        "src/privilege/path_hijack_detector.py",
        "src/privilege/service_scanner.py",
        "src/privilege/logon_script_detector.py",
        "src/api/privilege_routes.py",
    ]
    
    issues_found = 0
    for module in modules:
        if os.path.exists(module):
            analyze_module(module)
            issues_found += 1
        else:
            print(f"\n⚠ Module not found: {module}")
            print("  This might indicate incomplete Chapter 5 implementation")
    
    print(f"\n{'='*60}")
    print("SCAN COMPLETE")
    print('='*60)
    
    if issues_found == len(modules):
        print("✓ All expected modules exist and were analyzed")
    else:
        print(f"⚠ Only {issues_found}/{len(modules)} modules found")
    
    print("\nNext steps:")
    print("1. Fix any syntax errors found")
    print("2. Add missing docstrings")
    print("3. Replace bare except statements")
    print("4. Replace print() with logging")

if __name__ == "__main__":
    main()
