[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT&CK-red)](https://attack.mitre.org/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/Adrian-Obungu/mitre-attack-python-lab)](https://github.com/Adrian-Obungu/mitre-attack-python-lab/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Adrian-Obungu/mitre-attack-python-lab)](https://github.com/Adrian-Obungu/mitre-attack-python-lab/network/members)

# MITRE ATT&CK Detection Lab

A comprehensive educational and production-ready security detection framework built with Python.

## Overview

The MITRE ATT&CK Detection Lab is a modular Python framework for implementing, testing, and learning about MITRE ATT&CK technique detection. It is designed for three audiences:

1. **Security Beginners** - Learn detection engineering through hands-on code
2. **Enthusiasts** - Build and customize your own detection system
3. **Professionals** - Production-ready framework for enterprise detection

## Features

### Detection Capabilities
- **7+ MITRE ATT&CK techniques** implemented across 3 tactics
- **Defense Evasion (TA0005)**: T1027, T1070, T1112, T1140, T1197
- **Discovery (TA0007)**: T1016, T1033, T1049, T1057, T1082, T1135
- **Lateral Movement (TA0008)**: T1021, T1077, T1091
- Modular detector architecture for easy expansion

### Architecture
- **Modular Python classes** for each MITRE technique
- **SQLite state management** with historical tracking
- **Configurable alerting engine** with test mode
- **REST API** with authentication and RBAC
- **Comprehensive test suite** with 15+ test files

### Educational Value
- **Hands-on learning** through working code
- **Clear documentation** and quick start guides
- **MITRE ATT&CK mapping** with technique references
- **Community contribution** guidelines

### Production Ready
- **Docker support** for containerized deployment
- **CI/CD pipeline** with GitHub Actions
- **Type hints** and comprehensive docstrings
- **SIEM integration** capabilities

## Quick Start

### Installation
```bash
# Clone repository
git clone https://github.com/Adrian-Obungu/mitre-attack-python-lab.git
cd mitre-attack-python-lab

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Mac/Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage
```bash
# Run the API server
python src/api/main.py

# Test a detector directly
python -c "from src.defense_evasion.obfuscation_detector import T1027ObfuscationDetector
detector = T1027ObfuscationDetector()
result = detector.analyze({'process_name': 'test.exe'})
print(f'Detection result: {result}')"

# Run tests
pytest tests/
```

### Docker
```bash
# Build and run with Docker
docker build -t mitre-attack-lab .
docker run -p 8000:8000 mitre-attack-lab
```

## Project Structure
```
mitre-attack-python-lab/
├── src/                    # Source code
│   ├── api/               # FastAPI application
│   ├── core/              # State, alerting, factory
│   ├── defense_evasion/   # TA0005 detectors
│   ├── discovery/         # TA0007 detectors
│   ├── lateral_movement/  # TA0008 detectors
│   ├── compliance/        # Reporting engine
│   └── integrations/      # SIEM connectors
├── tests/                 # Comprehensive test suite
├── docs/                  # Documentation
├── scripts/               # Utility scripts
├── templates/             # Web dashboard
└── config/                # Configuration files
```

## MITRE ATT&CK Coverage

| Technique ID | Name | Tactic | Status |
|-------------|------|--------|--------|
| T1027 | Obfuscated Files or Information | Defense Evasion | Implemented |
| T1070 | Indicator Removal on Host | Defense Evasion | Implemented |
| T1112 | Modify Registry | Defense Evasion | Implemented |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | Implemented |
| T1197 | BITS Jobs | Defense Evasion | Implemented |
| T1087 | Account Discovery | Discovery | Implemented |
| T1135 | Network Share Discovery | Discovery | Implemented |
| T1016 | System Network Configuration Discovery | Discovery | Implemented |
| T1033 | System Owner/User Discovery | Discovery | Implemented |
| T1057 | Process Discovery | Discovery | Implemented |
| T1021 | Remote Services | Lateral Movement | Implemented |
| T1077 | Windows Admin Shares | Lateral Movement | Implemented |
| T1091 | Replication Through Removable Media | Lateral Movement | Implemented |

## Development

### Adding a New Detector
1. Create a new Python file in the appropriate tactic directory
2. Follow the detector template pattern
3. Add comprehensive tests
4. Update documentation

Example detector template:
```python
class TXXXXDetector:
    """Detector for Technique Name (TXXXX)"""
    
    def __init__(self):
        self.technique_id = "TXXXX"
        self.technique_name = "Technique Name"
        self.tactic = "Tactic Name"
    
    def analyze(self, data):
        """Analyze data for technique indicators"""
        # Your detection logic here
        pass
```

### Testing
```bash
# Run all tests
pytest

# Run specific test category
pytest tests/defense_evasion/
pytest tests/discovery/

# With coverage report
pytest --cov=src tests/
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- MITRE for maintaining the ATT&CK framework
- The security community for inspiration and feedback
- All contributors who help improve this project

## Support

- Open an [issue](https://github.com/Adrian-Obungu/mitre-attack-python-lab/issues) for bugs or questions
- Check the [docs](docs/) directory for documentation
- Review existing issues before creating new ones

---

**Built for the security community**