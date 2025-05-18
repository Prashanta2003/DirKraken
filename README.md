DirKraken
 
DirKraken is an automated penetration testing tool designed to evaluate the security of network infrastructure and web applications. It integrates Nmap, Nikto, and Metasploit to identify vulnerabilities such as open ports, outdated services, and web server misconfigurations, generating a consolidated Markdown report with mitigation recommendations.
Features

Nmap Scanning: Identifies open ports (1-1000), services, and versions.
Nikto Web Scanning: Detects web server vulnerabilities and misconfigurations.
Metasploit Attack Simulation: Simulates attacks to trigger IDS alerts.
Comprehensive Reporting: Generates a Markdown report with vulnerabilities and mitigation strategies.
Lightweight and Modular: Easy to extend with additional tools or scans.

Prerequisites

Operating System: Linux (Ubuntu/Debian recommended)
Python: Version 3.6+
Root Privileges: Required for Nmap and Metasploit operations
Dependencies:
Python module: python-nmap
Tools: nmap, nikto, metasploit-framework



Installation

Clone the Repository:
```
git clone https://github.com/yourusername/DirKraken.git
cd DirKraken
```

Install Python Dependencies:
```
pip3 install python-nmap
```
Install System Tools:
sudo apt update
sudo apt install nmap nikto metasploit-framework


Verify Dependencies:Ensure all tools are installed:
nmap --version
nikto -Version
msfconsole -v



Usage
Run DirKraken with a target IP or URL using sudo:
sudo python3 dirkraken.py -t <target>

Examples

Scan a local network IP:sudo python3 dirkraken.py -t 192.168.1.100


Scan a web server:sudo python3 dirkraken.py -t http://example.com



Output

Report: A Markdown report is generated at reports/vulnerability_report.md, detailing vulnerabilities and recommendations.
Nikto Output: Stored in reports/nikto_output.txt.

Sample Report
# Penetration Testing Report
**Date**: 2025-05-18 19:57:23
**Target**: 192.168.1.100

## Identified Vulnerabilities
1. Open port 80/http (Version: Apache 2.4.29) - Potential misconfiguration or outdated service.
2. Nikto: Server header exposes Apache/2.4.29 - Upgrade to latest version.

## Mitigation Recommendations
1. Close unnecessary open ports using firewall rules (e.g., iptables or ufw).
2. Update all services to the latest versions to patch known vulnerabilities.

Directory Structure
DirKraken/
├── dirkraken.py          # Main script
├── reports/              # Output directory for reports and scan logs
├── assets/               # Images and logos for documentation
├── LICENSE               # License file
└── README.md             # This file

Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a feature branch (git checkout -b feature-name).
Commit changes (git commit -m "Add feature").
Push to the branch (git push origin feature-name).
Open a Pull Request.

Please follow the Code of Conduct and ensure tests pass before submitting.
License
DirKraken is licensed under the MIT License.
Disclaimer
DirKraken is intended for authorized security testing only. Unauthorized use against systems without explicit permission is illegal. The developers are not responsible for misuse or damage caused by this tool.
Contact
For issues or suggestions, open an issue on the GitHub Issues page or contact the maintainer at your.email@example.com.
