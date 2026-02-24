[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT&CK-red)](https://attack.mitre.org/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/Adrian-Obungu/mitre-attack-python-lab)](https://github.com/Adrian-Obungu/mitre-attack-python-lab/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Adrian-Obungu/mitre-attack-python-lab)](https://github.com/Adrian-Obungu/mitre-attack-python-lab/network/members)

# MITRE ATT&CK Detection Lab

A robust, Python-based framework designed for advanced security detection engineering, threat emulation, and defensive posture validation against MITRE ATT&CK techniques.

## Overview

The MITRE ATT&CK Detection Lab serves as a modular, extensible platform for developing, testing, and operationalizing detection logic aligned with the MITRE ATT&CK framework. It caters to a diverse audience, from security researchers and detection engineers seeking to deepen their understanding of adversary tactics to organizations aiming to enhance their threat detection capabilities and validate security controls.

## Features

### Core Capabilities
- **Comprehensive Technique Coverage:** Implements a growing suite of MITRE ATT&CK techniques across key tactics, including Defense Evasion (TA0005), Discovery (TA0007), and Privilege Escalation (TA0004), with specific techniques such as T1027, T1070, T1112, T1140, T1197, T1087, T1135, T1016, T1033, T1057, T1021, T1077, T1091, T1037, T1073.001, T1543.003, and T1053.005.
- **Extensible Detector Architecture:** Features a modular design that facilitates the rapid development and integration of new detection modules, ensuring adaptability to evolving threat landscapes.

### Architectural Design
- **Microservice-Oriented Detection:** Each MITRE ATT&CK technique is encapsulated within dedicated Python classes, promoting modularity and independent development.
- **Persistent State Management:** Leverages SQLite for robust state management, enabling historical tracking of detection events and contextual data.
- **Advanced Alerting Engine:** Incorporates a configurable alerting mechanism with a dedicated test mode, allowing for fine-tuned notification strategies.
- **Secure RESTful API:** Provides a FastAPI-based REST API, secured with API key authentication, offering programmatic access to detection functionalities and facilitating integration into broader security ecosystems.
- **Rigorous Testing Framework:** Supported by a comprehensive test suite, ensuring the reliability and accuracy of detection logic.

### Strategic Value
- **Empirical Detection Engineering:** Offers a practical environment for hands-on learning and experimentation with detection engineering principles.
- **Threat Intelligence Alignment:** Directly maps implemented detections to MITRE ATT&CK techniques, providing clear references and enhancing threat intelligence integration.
- **Community-Driven Development:** Encourages contributions and collaborative enhancement of detection capabilities.

### Operational Readiness
- **Containerized Deployment:** Includes Docker support for streamlined, portable deployment across various environments.
- **Automated Quality Assurance:** Integrates a CI/CD pipeline with GitHub Actions to ensure code quality, consistency, and continuous validation.
- **Code Quality and Maintainability:** Adheres to best practices with extensive type hints and comprehensive docstrings, promoting code readability and long-term maintainability.
- **Seamless SIEM Integration:** Designed with capabilities for straightforward integration into Security Information and Event Management (SIEM) platforms, enabling centralized logging and alert correlation.

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