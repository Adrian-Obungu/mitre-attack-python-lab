#!/usr/bin/env python3
"""Fix logger definition issue in privilege_auditor.py"""

with open('src/privilege/privilege_auditor.py', 'r') as f:
    lines = f.readlines()

# Find where logger is used before definition
# Looking for line with: logger.warning("winreg module not available...")
fixed_lines = []
logger_defined = False

for line in lines:
    # Check if this is the problem line
    if 'logger.warning(' in line and not logger_defined:
        # We need to define logger before this line
        # Let's insert logger definition
        fixed_lines.append('# Setup basic logging for the module\n')
        fixed_lines.append('# This will be overridden by structured JSON logging in main application\n')
        fixed_lines.append('import logging\n')
        fixed_lines.append('logger = logging.getLogger(__name__)\n')
        fixed_lines.append('if not logger.handlers:\n')
        fixed_lines.append('    logger.setLevel(logging.INFO)\n')
        fixed_lines.append('    handler = logging.StreamHandler(sys.stdout)\n')
        fixed_lines.append('    formatter = logging.Formatter(\'%(asctime)s - %(name)s - %(levelname)s - %(message)s\')\n')
        fixed_lines.append('    handler.setFormatter(formatter)\n')
        fixed_lines.append('    logger.addHandler(handler)\n')
        fixed_lines.append('\n')
        logger_defined = True
    
    # Remove any duplicate logger definitions
    if line.strip().startswith('logger = logging.getLogger') and logger_defined:
        continue  # Skip duplicate
    
    fixed_lines.append(line)

# Write the fixed file
with open('src/privilege/privilege_auditor.py', 'w') as f:
    f.writelines(fixed_lines)

print("Fixed logger definition issue in privilege_auditor.py")
