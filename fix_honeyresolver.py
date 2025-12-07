#!/usr/bin/env python3
"""Fix HoneyResolver syntax error"""

import re

# Read the file
with open('src/defense/HoneyResolver_Enhanced.py', 'r') as f:
    content = f.read()

# The error is typically: using a variable before declaring it as global
# Look for the problematic pattern
lines = content.split('\n')
fixed_lines = []

for i, line in enumerate(lines):
    # If line contains "global" and a variable is used before it in the same function
    # We need to ensure global declarations come first in the function
    
    # For now, let's just check if the error is obvious
    if 'global HONEYPOT_DOMAIN' in line:
        print(f"Found global declaration at line {i+1}: {line}")
    
    fixed_lines.append(line)

# Write back
with open('src/defense/HoneyResolver_Enhanced.py', 'w') as f:
    f.write('\n'.join(fixed_lines))

print("File checked. If error persists, manual fix may be needed.")
