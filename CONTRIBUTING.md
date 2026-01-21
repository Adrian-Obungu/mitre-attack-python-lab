# Contributing to MITRE ATT&CK Lab

Thank you for your interest in contributing! This project is designed to be educational and community-driven.

## How to Contribute

### 1. Report Bugs
- Use GitHub Issues
- Include: Python version, error message, steps to reproduce
- Check if issue already exists

### 2. Suggest Features
- Open an issue with "[Feature Request]" prefix
- Describe the use case
- Suggest implementation approach if possible

### 3. Submit Code Changes
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: \`pytest\`
6. Submit a Pull Request

### 4. Add MITRE Techniques
We welcome contributions of new MITRE ATT&CK technique detectors!

Template for new detectors:
\`\`\`python
"""
TXXXX: Technique Name
Tactic: Tactic Name
Reference: https://attack.mitre.org/techniques/TXXXX/
"""

class TXXXXDetector:
    """Detector for Technique Name"""
    
    def __init__(self):
        self.technique_id = "TXXXX"
        self.technique_name = "Technique Name"
        self.tactic = "Tactic Name"
    
    def analyze(self, data):
        """Analyze data for technique indicators"""
        # Your detection logic here
        pass
\`\`\`

### Development Setup
\`\`\`bash
# Clone and setup
git clone https://github.com/yourusername/mitre-attack-python-lab.git
cd mitre-attack-python-lab
python -m venv venv
source venv/Scripts/activate  # Windows
source venv/bin/activate      # Mac/Linux
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src/ tests/

# Check code quality
flake8 src/
mypy src/
\`\`\`

### Code Style
- Follow PEP 8
- Use type hints
- Add docstrings to public functions
- Write unit tests for new features

### Pull Request Process
1. Update README.md if needed
2. Update CHANGELOG.md
3. Ensure CI passes
4. Request review from maintainers

## Questions?
- Open a GitHub Discussion
- Check existing documentation
- Review open/closed issues

Happy detecting! Ìª°Ô∏è
