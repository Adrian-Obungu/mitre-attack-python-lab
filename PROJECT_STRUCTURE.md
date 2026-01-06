# MITRE ATT&CK Python Lab - Project Structure

## ��� Directory Layout
mitre-attack-python-lab/
├── src/
│ ├── reconnaissance/ # Chapter 1: DNS/Port Scanning
│ │ ├── dns_recon.py # Multi-threaded DNS reconnaissance
│ │ ├── tcp_connect_scan.py # Windows-safe TCP scanner
│ │ └── PortScan_Enhanced.py # Raw socket scanner (admin required)
│ ├── persistence/ # Chapter 4: Persistence Detection
│ │ └── persistence_auditor.py # Windows persistence auditor
│ ├── defense/ # Chapter 2-3: Defensive Tools
│ │ └── HoneyResolver_Enhanced.py # DNS honeypot
│ ├── utils/ # Shared utilities
│ │ ├── log_parser.py # JSON threat analysis
│ │ └── threat_intel.py # AbuseIPDB/VirusTotal integration
│ └── api_server.py # FastAPI orchestration layer
├── config/ # Configuration files
│ ├── common_subdomains.txt # DNS wordlist
│ ├── persistence_allowlist.json
│ └── requirements.txt
├── logs/ # Application logs
├── engagements/ # Real-world assessment templates
├── venv/ # Virtual environment
├── .env # Environment variables
├── .gitignore # Git ignore rules
├── Dockerfile # Container configuration
└── README.md # Project documentation

text

## ��� Chapter Integration Status
- ✅ **Chapter 1**: DNS/Port Reconnaissance - Integrated
- ✅ **Chapter 4**: Persistence Detection - Integrated  
- ��� **Chapter 5**: Privilege Escalation - READY FOR IMPLEMENTATION
- ⏳ **Chapter 6**: Defense Evasion - QUEUED
- ⏳ **Chapter 9**: Lateral Movement - QUEUED
- ⏳ **Chapter 11-12**: C2/Exfiltration - QUEUED

## ��� Development Workflow
1. **Environment**: Use `venv/Scripts/python` for all execution
2. **Testing**: Run `validate_environment.py` after changes
3. **Validation**: All core modules must pass end-to-end tests
4. **Documentation**: Update relevant files with new capabilities
5. **Git**: Commit with descriptive messages, push to origin

## ��� Next Priority: Chapter 5 (Privilege Escalation)
**Target Module**: `src/privilege/privilege_auditor.py`
**MITRE Techniques**: T1548, T1037, T1073.001
**Features**:
- Logon script detection (Windows registry)
- Python path hijacking detection
- Service misconfiguration analysis
- API endpoint: `/privilege/scan`
