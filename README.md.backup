# 🛡️ MITRE ATT&CK Python Security Lab

![Python Version](https://img.shields.io/badge/Python-3.9+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT&CK®-Framework-orange.svg)

A comprehensive cybersecurity lab for simulating, detecting, and understanding adversary tactics and techniques based on the MITRE ATT&CK® framework. This repository provides a suite of Python-based tools for both offensive reconnaissance and defensive threat detection, designed for security professionals, researchers, and students.

---

### 🚀 Quick Start

Get up and running in minutes. Clone the repository, set up the environment, and run your first scan.

```bash
# Clone the repository
git clone https://github.com/your-username/mitre-attack-python-lab.git
cd mitre-attack-python-lab

# Set up virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt # (Assuming a requirements.txt file exists)

# Configure your API keys
cp .env.example .env
# nano .env

# Run the enhanced port scanner in demo mode
python src/reconnaissance/PortScan_Enhanced.py --type syn --demo
```

---

## ✨ Features

This lab is equipped with a growing set of tools to simulate and counteract real-world cyber threats.

| Offensive Capabilities (Reconnaissance) ⚔️                                 | Defensive Capabilities (Threat Detection) 🛡️                             |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------- |
| ✅ **Enhanced Port Scanner** (`SYN`, `ACK`, `XMAS` scans)                  | ✅ **DNS Honeypot Resolver** (Detects and logs suspicious DNS queries)   |
| ✅ **DNS Reconnaissance** (Gather `A`, `AAAA`, `MX`, `TXT`, `NS` records) | ✅ **Log Analytics & Threat Scoring** (Parses logs to identify threats)  |
| ✅ **Common Subdomain List** (`50+` common names for enumeration)        | ✅ **Enterprise-Grade Logging** (Structured logs for SIEM integration) |
| ✅ **Privilege Escalation Auditor** (Detects Windows PE vectors)        |

---

## 🗺️ MITRE ATT&CK® Mapping

The tools in this lab are directly mapped to specific MITRE ATT&CK techniques, providing a practical way to study and understand adversary behavior.

| Technique ID | Tactic                               | Description                                                                                              | Associated Tool                                     |
| :----------- | :----------------------------------- | :------------------------------------------------------------------------------------------------------- | :-------------------------------------------------- |
| **T1595**    | Active Scanning                      | The adversary probes victim infrastructure to identify vulnerabilities and discover information.           | `PortScan_Enhanced.py` (`syn`, `ack`, `xmas`)       |
| **T1046**    | Network Service Scanning             | The adversary attempts to identify listening ports and services to find potential vulnerabilities.       | `PortScan_Enhanced.py` (`syn`, `xmas`)              |
| **T1590**    | Gather Victim Host Information       | The adversary collects information about the victim's hosts, such as DNS records.                        | `PortScan_Enhanced.py` (`dns`)                      |
| **T1018** | Remote System Discovery | An adversary may attempt to get a listing of other systems by IP address, hostname, or other means.    | `HoneyResolver_Enhanced.py` (Detects this behavior) |
| **T1037**    | Boot or Logon Autostart Execution | Adversaries may use logon scripts to establish persistence.                                             | `privilege_auditor.py`                       |
| **T1073.001**| DLL Hijacking                     | Adversaries may hijack the Python search order to execute malicious code.                              | `privilege_auditor.py`                       |
| **T1543.003**| Create or Modify System Process   | Adversaries may create or modify Windows services to execute malicious code.                           | `privilege_auditor.py`                       |
| **T1053.005**| Scheduled Task/Job                | Adversaries may abuse scheduled tasks to execute programs at system startup or at a given time.      | `privilege_auditor.py`                       |
| **T1548.002**| Bypass User Account Control       | Adversaries may bypass UAC mechanisms to execute programs with elevated privileges.                    | `privilege_auditor.py`                       |

---

## ⚙️ Installation

Follow these steps to set up your local lab environment.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/mitre-attack-python-lab.git
    cd mitre-attack-python-lab
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
    *On Windows, use `venv\Scripts\activate`*

3.  **Install dependencies:**
    The project uses `google-generativeai`, `scapy`, `dnslib`, and `dnspython`.
    ```bash
    pip install google-generativeai scapy dnslib dnspython pytest
    ```

4.  **Configure Environment Variables:**
    Create a `.env` file to store your API keys.
    ```bash
    echo "GEMINI_API_KEY=your_api_key_here" > .env
    echo "GITHUB_TOKEN=your_github_token_here" >> .env
    ```
    Replace `your_api_key_here` with your actual API keys.

---

## 🔬 Usage Examples

### Enhanced Port Scanner

Perform various scans to identify services and firewalls.

**SYN Scan (Stealth Scan):**
```bash
python src/reconnaissance/PortScan_Enhanced.py --target scanme.nmap.org --ports 22,80,443 --type syn
```
![Usage screenshot of Port Scanner](https://via.placeholder.com/800x300.png?text=Port+Scanner+SYN+Scan+Output)

**ACK Scan (Firewall Detection):**
```bash
python src/reconnaissance/PortScan_Enhanced.py --target scanme.nmap.org --ports 80,443 --type ack
```
![Usage screenshot of ACK Scan](https://via.placeholder.com/800x300.png?text=Port+Scanner+ACK+Scan+Output)

### DNS Honeypot Resolver

Start the honeypot to listen for and log suspicious DNS queries.

**Run the Honeypot:**
```bash
sudo python src/defense/HoneyResolver_Enhanced.py --domain my-honeypot.net
```
![Usage screenshot of DNS Honeypot](https://via.placeholder.com/800x300.png?text=DNS+Honeypot+Running)

**Analyze Logs:**
Use the log parser to analyze the `honeyresolver.log` file and score threats.
```bash
python src/utils/log_parser.py honeyresolver.log
```
![Usage screenshot of Log Analyzer](https://via.placeholder.com/800x300.png?text=Log+Analyzer+Report)

---

## 🤝 Contributing

Contributions are welcome! If you have ideas for new tools, improvements, or bug fixes, please follow these steps:
1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/your-feature-name`).
3.  Commit your changes (`git commit -m 'Add some feature'`).
4.  Push to the branch (`git push origin feature/your-feature-name`).
5.  Open a Pull Request.

Please open an issue first to discuss any significant changes.

---

## ⚠️ Security and Legal Disclaimer

This repository contains tools designed for security research and educational purposes only. The misuse of these tools can result in serious legal consequences.

-   **DO NOT** use these tools on any network or system without explicit, written permission from the owner.
-   The author is not responsible for any damage or legal issues caused by the misuse of this software.
-   By using this software, you agree to take full responsibility for your actions.

---

## ✍️ Author

This project is maintained by **Adrian S. Obungu**.

[GitHub Profile](https://github.com/Adrian-Obungu) | [LinkedIn](https://www.linkedin.com/in/adrian-o-9b4856260/)
