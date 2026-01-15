#!/usr/bin/env python3
"""
Diagnostic script to capture current state of Chapter 5 implementation
"""

import os
import sys
import json
import traceback

def check_file_exists(path):
    return os.path.exists(path)

def check_import(path, module_path, class_name=None):
    """Check if a module can be imported"""
    try:
        sys.path.insert(0, os.path.dirname(path) if os.path.isdir(path) else path)
        module = __import__(module_path, fromlist=[class_name] if class_name else [])
        if class_name and hasattr(module, class_name):
            return True, f"✓ {module_path}.{class_name}"
        elif not class_name:
            return True, f"✓ {module_path}"
        else:
            return False, f"✗ {module_path} - {class_name} not found"
    except ImportError as e:
        return False, f"✗ {module_path} - ImportError: {e}"
    except Exception as e:
        return False, f"✗ {module_path} - Error: {e}"

def check_file_syntax(filepath):
    """Check Python file syntax"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            compile(f.read(), filepath, 'exec')
        return True, "Syntax OK"
    except SyntaxError as e:
        return False, f"Syntax error: {e}"
    except Exception as e:
        return False, f"Error reading: {e}"

def analyze_imports(filepath):
    """Analyze import statements in a file"""
    issues = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if line.startswith('from ') or line.startswith('import '):
                    if 'src.' in line and filepath.startswith('src/'):
                        issues.append(f"Line {i}: Absolute import in module - {line}")
                    if 'from .' in line and 'try:' not in lines[i-2] if i>2 else True:
                        issues.append(f"Line {i}: Relative import may fail when run directly - {line}")
    except Exception as e:
        issues.append(f"Error analyzing imports: {e}")
    return issues

def get_methods(filepath, class_name):
    """Get methods defined in a class"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Simple extraction of class methods
        lines = content.split('\n')
        methods = []
        in_target_class = False
        indent_level = 0
        
        for line in lines:
            stripped = line.strip()
            
            # Check if we're entering the target class
            if stripped.startswith(f'class {class_name}'):
                in_target_class = True
                indent_level = len(line) - len(line.lstrip())
                continue
            
            if in_target_class:
                # Check if we've left the class
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= indent_level and stripped and not stripped.startswith('def '):
                    break
                
                # Check for method definitions
                if stripped.startswith('def '):
                    method_name = stripped.split('def ')[1].split('(')[0].strip()
                    if not method_name.startswith('_'):
                        methods.append(method_name)
        
        return methods
    except Exception as e:
        return [f"Error: {e}"]

def main():
    print("Chapter 5 - Current State Diagnostic")
    print("=" * 60)
    
    diagnostics = {
        "files_exist": {},
        "imports_work": [],
        "syntax_errors": [],
        "import_issues": {},
        "missing_methods": {},
        "current_errors": []
    }
    
    # Check critical files
    critical_files = [
        "src/privilege/privilege_auditor.py",
        "src/privilege/path_hijack_detector.py",
        "src/privilege/service_scanner.py",
        "src/privilege/logon_script_detector.py",
        "src/api/main.py",
        "src/api/routes/privilege_routes.py",
        "Dockerfile",
        "requirements.txt"
    ]
    
    print("\n1. File Existence Check:")
    for file in critical_files:
        exists = check_file_exists(file)
        diagnostics["files_exist"][file] = exists
        status = "✓" if exists else "✗"
        print(f"   {status} {file}")
    
    print("\n2. Syntax Check:")
    for file in critical_files:
        if check_file_exists(file):
            ok, msg = check_file_syntax(file)
            if not ok:
                diagnostics["syntax_errors"].append(f"{file}: {msg}")
                print(f"   ✗ {file}: {msg}")
    
    print("\n3. Import Analysis:")
    # Check privilege_auditor.py imports
    if check_file_exists("src/privilege/privilege_auditor.py"):
        issues = analyze_imports("src/privilege/privilege_auditor.py")
        if issues:
            diagnostics["import_issues"]["privilege_auditor.py"] = issues
            print(f"   Issues in privilege_auditor.py:")
            for issue in issues[:3]:  # Show first 3
                print(f"     - {issue}")
    
    print("\n4. Method Check:")
    # Check if scan method exists in key classes
    classes_to_check = [
        ("src/privilege/privilege_auditor.py", "PrivilegeAuditor", ["scan"]),
        ("src/privilege/path_hijack_detector.py", "PathHijackDetector", ["scan"]),
        ("src/privilege/service_scanner.py", "ServiceScanner", ["scan"]),
    ]
    
    for file, class_name, required_methods in classes_to_check:
        if check_file_exists(file):
            methods = get_methods(file, class_name)
            missing = [m for m in required_methods if m not in methods]
            if missing:
                diagnostics["missing_methods"][f"{file}:{class_name}"] = missing
                print(f"   ✗ {class_name} missing methods: {missing}")
            else:
                print(f"   ✓ {class_name} has required methods")
    
    print("\n5. Current Runtime Errors:")
    # Try to run privilege_auditor with --help
    try:
        import subprocess
        result = subprocess.run(
            [sys.executable, "src/privilege/privilege_auditor.py", "--help"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            error_msg = result.stderr[:200] if result.stderr else "Unknown error"
            diagnostics["current_errors"].append(f"privilege_auditor.py --help failed: {error_msg}")
            print(f"   ✗ privilege_auditor.py --help failed: {error_msg}")
        else:
            print(f"   ✓ privilege_auditor.py --help works")
    except Exception as e:
        diagnostics["current_errors"].append(f"Runtime test failed: {e}")
        print(f"   ✗ Runtime test failed: {e}")
    
    # Save diagnostics to file
    with open('chapter5_diagnostics.json', 'w') as f:
        json.dump(diagnostics, f, indent=2)
    
    print(f"\n{'='*60}")
    print("Diagnostics saved to chapter5_diagnostics.json")
    print("\nSummary of issues to fix:")
    print("-" * 40)
    
    issue_count = 0
    if diagnostics["syntax_errors"]:
        print(f"Syntax errors: {len(diagnostics['syntax_errors'])}")
        issue_count += len(diagnostics["syntax_errors"])
    
    for file, issues in diagnostics["import_issues"].items():
        print(f"Import issues in {file}: {len(issues)}")
        issue_count += len(issues)
    
    for class_info, missing in diagnostics["missing_methods"].items():
        print(f"Missing methods in {class_info}: {missing}")
        issue_count += len(missing)
    
    for error in diagnostics["current_errors"]:
        print(f"Runtime error: {error}")
        issue_count += 1
    
    print(f"\nTotal issues identified: {issue_count}")
    
    return diagnostics

if __name__ == "__main__":
    main()
