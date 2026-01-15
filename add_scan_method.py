#!/usr/bin/env python3
"""Add scan method to PrivilegeAuditor if missing"""

import re

with open('src/privilege/privilege_auditor.py', 'r') as f:
    content = f.read()

# Check if scan method exists
if 'def scan(' not in content:
    print("Adding scan method to PrivilegeAuditor...")
    
    # Find where to add the method (after __init__)
    lines = content.split('\n')
    new_lines = []
    in_init = False
    init_closed = False
    brace_count = 0
    
    for line in lines:
        new_lines.append(line)
        
        # Check if we're in __init__ method
        if 'def __init__' in line:
            in_init = True
        
        if in_init:
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0 and line.strip() and not line.strip().startswith('def '):
                in_init = False
                init_closed = True
        
        # Add scan method right after __init__ closes
        if init_closed and 'def ' not in line and line.strip() == '':
            # Add scan method here
            new_lines.append('')
            new_lines.append('    def scan(self):')
            new_lines.append('        """')
            new_lines.append('        Execute comprehensive privilege escalation scan')
            new_lines.append('        ')
            new_lines.append('        Returns:')
            new_lines.append('            List of PrivilegeFinding objects')
            new_lines.append('        """')
            new_lines.append('        findings = []')
            new_lines.append('        ')
            new_lines.append('        try:')
            new_lines.append('            # Check for path hijacking')
            new_lines.append('            path_detector = PathHijackDetector()')
            new_lines.append('            path_findings = path_detector.scan()')
            new_lines.append('            findings.extend(path_findings)')
            new_lines.append('            ')
            new_lines.append('            # Check service permissions')
            new_lines.append('            service_scanner = ServiceScanner()')
            new_lines.append('            service_findings = service_scanner.scan()')
            new_lines.append('            findings.extend(service_findings)')
            new_lines.append('            ')
            new_lines.append('            # Check logon scripts')
            new_lines.append('            from src.privilege.logon_script_detector import LogonScriptDetector')
            new_lines.append('            logon_detector = LogonScriptDetector()')
            new_lines.append('            logon_findings = logon_detector.scan()')
            new_lines.append('            findings.extend(logon_findings)')
            new_lines.append('            ')
            new_lines.append('        except Exception as e:')
            new_lines.append('            logger.error(f"Error during privilege scan: {e}")')
            new_lines.append('            ')
            new_lines.append('        return findings')
            new_lines.append('')
            init_closed = False  # Reset flag
    
    # Write the updated file
    with open('src/privilege/privilege_auditor.py', 'w') as f:
        f.write('\n'.join(new_lines))
    
    print("✓ Added scan method to PrivilegeAuditor")
else:
    print("✓ scan method already exists")
