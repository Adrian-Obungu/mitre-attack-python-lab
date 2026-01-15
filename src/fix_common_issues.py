#!/usr/bin/env python3
"""Fix common issues in Chapter 5 implementation"""

import os
import re

def fix_imports(filepath):
    """Fix import issues in a file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Fix common import patterns
    fixes_made = []
    
    # Fix: Change relative imports to absolute if they're problematic
    lines = content.split('\n')
    fixed_lines = []
    
    for line in lines:
        fixed_line = line
        
        # Fix: from . import X -> from src.privilege import X (if in privilege module)
        if filepath.startswith('src/privilege/') and 'from . import' in line:
            module_name = filepath.split('/')[-1].replace('.py', '')
            fixed_line = line.replace('from . import', 'from src.privilege import')
            fixes_made.append(f"Fixed relative import in {filepath}")
        
        # Fix: bare except statements
        if 'except:' in line and 'except Exception:' not in line:
            fixed_line = line.replace('except:', 'except Exception:')
            fixes_made.append(f"Fixed bare except in {filepath}")
        
        fixed_lines.append(fixed_line)
    
    if fixes_made:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(fixed_lines))
    
    return fixes_made

def add_docstrings(filepath):
    """Add missing docstrings to classes and functions"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.split('\n')
    fixed_lines = []
    fixes_made = []
    
    i = 0
    while i < len(lines):
        line = lines[i]
        fixed_lines.append(line)
        
        # Check for class definition without docstring
        if line.strip().startswith('class ') and i+1 < len(lines):
            next_line = lines[i+1].strip()
            if not next_line.startswith('\"\"\"') and not next_line.startswith('\'\'\''):
                # Add docstring
                class_name = line.split('class ')[1].split('(')[0].split(':')[0].strip()
                docstring = f'    \"\"\"{class_name} - Detects privilege escalation vectors\"\"\"'
                fixed_lines.append(docstring)
                fixes_made.append(f"Added docstring to class {class_name} in {filepath}")
                # Skip the next line since we added it
                i += 1
                continue
        
        # Check for function definition without docstring
        elif line.strip().startswith('def ') and not line.strip().startswith('def __') and i+1 < len(lines):
            next_line = lines[i+1].strip()
            if not next_line.startswith('\"\"\"') and not next_line.startswith('\'\'\''):
                # Add docstring
                func_name = line.split('def ')[1].split('(')[0].strip()
                docstring = f'    \"\"\"{func_name} - Check for privilege escalation\"\"\"'
                fixed_lines.append(docstring)
                fixes_made.append(f"Added docstring to function {func_name} in {filepath}")
                # Skip the next line since we added it
                i += 1
                continue
        
        i += 1
    
    if fixes_made:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(fixed_lines))
    
    return fixes_made

def fix_print_statements(filepath):
    """Replace print statements with logging"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    fixes_made = []
    
    # Check if logging is imported
    if 'print(' in content and 'import logging' not in content:
        # Add logging import at the top
        lines = content.split('\n')
        fixed_lines = []
        logging_added = False
        
        for line in lines:
            fixed_lines.append(line)
            
            # Add logging import after other imports
            if line.strip().startswith('import ') or line.strip().startswith('from '):
                if not logging_added and 'logging' not in line:
                    # Add logging import on next line
                    fixed_lines.append('import logging')
                    logging_added = True
                    fixes_made.append(f"Added logging import to {filepath}")
        
        content = '\n'.join(fixed_lines)
    
    # Replace print statements with logging
    if 'print(' in content and 'import logging' in content:
        # Simple replacement - in reality would need more sophisticated parsing
        new_content = re.sub(r'print\((.*)\)', r'logging.info(\1)', content)
        
        if new_content != content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            fixes_made.append(f"Replaced print statements with logging in {filepath}")
    
    return fixes_made

def main():
    print("Chapter 5 Implementation - Fix Common Issues")
    print("=" * 60)
    
    modules = [
        "src/privilege/privilege_auditor.py",
        "src/privilege/path_hijack_detector.py", 
        "src/privilege/service_scanner.py",
        "src/privilege/logon_script_detector.py",
    ]
    
    all_fixes = []
    
    for module in modules:
        if os.path.exists(module):
            print(f"\nFixing: {module}")
            print("-" * 40)
            
            fixes = fix_imports(module)
            all_fixes.extend(fixes)
            
            fixes = add_docstrings(module)
            all_fixes.extend(fixes)
            
            fixes = fix_print_statements(module)
            all_fixes.extend(fixes)
            
            if fixes:
                print(f"  Applied {len(fixes)} fixes")
            else:
                print("  No fixes needed")
        else:
            print(f"\n⚠ Module not found: {module}")
    
    print(f"\n{'='*60}")
    print("FIXES APPLIED SUMMARY")
    print('='*60)
    
    if all_fixes:
        print(f"Applied {len(all_fixes)} fixes:")
        for fix in all_fixes:
            print(f"  ✓ {fix}")
    else:
        print("No fixes were needed")
    
    print("\nNext: Run tests to verify fixes didn't break anything")

if __name__ == "__main__":
    main()
