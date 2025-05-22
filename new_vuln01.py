#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
import sys
from datetime import datetime
try:
    import nmap
except ImportError:
    print("Error: python-nmap is not installed. Install it with: pip3 install python-nmap")
    sys.exit(1)

# Configuration
REPORT_PATH = "reports/vulnerability_report.md"
NIKTO_OUTPUT = "reports/nikto_output.txt"
VULNERABILITIES = []
NIKTO_TIMEOUT = 500  # 5 minutes
MSF_TIMEOUT = 300  # 2 minutes

def check_dependencies():
    """Check if required tools are installed."""
    tools = {
        "nmap": "nmap",
        "nikto": "nikto",
        "msfconsole": "metasploit-framework"
    }
    missing = []
    for tool, package in tools.items():
        try:
            subprocess.run([tool, "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing.append(f"{tool} (install with: sudo apt install {package})")
    if missing:
        print("Error: Missing dependencies:")
        for m in missing:
            print(f"- {m}")
        sys.exit(1)

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Automated Penetration Testing Script")
    parser.add_argument("-t", "--target", required=True, help="Target IP or URL (e.g., 192.168.1.100 or http://example.com)")
    return parser.parse_args()

def validate_target(target):
    """Validate if target is a valid IP or URL."""
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    url_pattern = r"^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(ip_pattern, target) or re.match(url_pattern, target))

def run_nmap_scan(target):
    """Run Nmap scan to identify open ports and services."""
    print(f"Starting Nmap scan on {target}...")
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-p 1-1000 -sV -sC --open -T4")
        for host in nm.all_hosts():
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    service = nm[host]['tcp'][port].get('name', 'unknown')
                    version = nm[host]['tcp'][port].get('version', 'unknown')
                    state = nm[host]['tcp'][port]['state']
                    if state == 'open':
                        VULNERABILITIES.append(
                            f"Open port {port}/{service} (Version: {version}) - "
                            f"Potential misconfiguration or outdated service."
                        )
        print("Nmap scan completed.")
    except nmap.PortScannerError as e:
        print(f"Nmap scan failed: {e}")
        VULNERABILITIES.append(f"Nmap scan error: {str(e)}")
    except Exception as e:
        print(f"Unexpected Nmap error: {e}")
        VULNERABILITIES.append(f"Nmap unexpected error: {str(e)}")

def run_nikto_scan(target):
    """Run Nikto scan for web vulnerabilities."""
    print(f"Starting Nikto scan on {target}...")
    try:
        # Ensure target has http:// or https:// prefix
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        nikto_cmd = [
            "nikto", "-h", target, "-Tuning", "1239ab", "-o",
            NIKTO_OUTPUT, "-F", "txt", "-timeout", str(NIKTO_TIMEOUT)
        ]
        result = subprocess.run(nikto_cmd, capture_output=True, text=True, timeout=NIKTO_TIMEOUT)
        if result.returncode == 0:
            try:
                with open(NIKTO_OUTPUT, "r") as f:
                    for line in f:
                        if "+ " in line and ("OSVDB" in line or "ERROR" not in line):
                            VULNERABILITIES.append(f"Nikto: {line.strip()}")
                print("Nikto scan completed.")
            except FileNotFoundError:
                VULNERABILITIES.append("Nikto: Output file not found.")
        else:
            print(f"Nikto scan failed: {result.stderr}")
            VULNERABILITIES.append(f"Nikto scan error: {result.stderr}")
    except subprocess.TimeoutExpired:
        print("Nikto scan timed out.")
        VULNERABILITIES.append("Nikto scan timed out.")
    except FileNotFoundError:
        print("Error: Nikto is not installed or not in PATH.")
        VULNERABILITIES.append("Nikto not installed.")
    except Exception as e:
        print(f"Nikto scan failed: {e}")
        VULNERABILITIES.append(f"Nikto scan error: {str(e)}")

def simulate_attacks(target):
    """Simulate attacks using Metasploit."""
    print("Simulating attacks to trigger IDS...")
    attacks = [
        "auxiliary/scanner/ftp/anonymous",
        "auxiliary/scanner/http/dir_listing",
        "auxiliary/scanner/smb/smb_version",
        "auxiliary/scanner/ssh/ssh_version",
        "auxiliary/scanner/http/http_version"
    ]
    for module in attacks:
        try:
            subprocess.run([
                "msfconsole", "-q", "-x",
                f"use {module};set RHOSTS {target};run;exit"
            ], timeout=MSF_TIMEOUT, check=True, capture_output=True, text=True)
            VULNERABILITIES.append(f"Triggered IDS alert for {module}.")
        except subprocess.TimeoutExpired:
            print(f"Timeout on {module}.")
            VULNERABILITIES.append(f"Metasploit timeout on {module}.")
        except subprocess.CalledProcessError as e:
            print(f"Metasploit failed on {module}: {e.stderr}")
            VULNERABILITIES.append(f"Metasploit error on {module}: {e.stderr}")
        except FileNotFoundError:
            print("Error: msfconsole is not installed or not in PATH.")
            VULNERABILITIES.append("Metasploit not installed.")
    print("Attack simulation completed.")

def generate_report(target):
    """Generate a Markdown report."""
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        f.write("# Penetration Testing Report\n")
        f.write(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Target**: {target}\n\n")
        f.write("## Identified Vulnerabilities\n")
        if VULNERABILITIES:
            for i, vuln in enumerate(VULNERABILITIES, 1):
                f.write(f"{i}. {vuln}\n")
        else:
            f.write("No vulnerabilities identified.\n")
        f.write("\n## Mitigation Recommendations\n")
        mitigations = [
            "Close unnecessary open ports using firewall rules (e.g., iptables or ufw).",
            "Update all services to the latest versions to patch known vulnerabilities.",
            "Disable anonymous access to FTP, SMB, and other services.",
            "Implement strong password policies and enforce multi-factor authentication.",
            "Replace unencrypted protocols (e.g., Telnet, HTTP) with secure alternatives (e.g., SSH, HTTPS).",
            "Regularly monitor logs and deploy IDS/IPS to detect suspicious activity."
        ]
        for i, mitigation in enumerate(mitigations, 1):
            f.write(f"{i}. {mitigation}\n")
    print(f"Report generated at {REPORT_PATH}")

def main():
    """Main function."""
    if os.geteuid() != 0:
        print("This script requires root privileges. Run with sudo.")
        sys.exit(1)

    check_dependencies()
    args = parse_args()
    target = args.target

    if not validate_target(target):
        print("Invalid target. Provide a valid IP (e.g., 192.168.1.100) or URL (e.g., http://example.com).")
        sys.exit(1)

    run_nmap_scan(target)
    run_nikto_scan(target)
    simulate_attacks(target)
    generate_report(target)
    print("Penetration testing completed successfully.")

if __name__ == "__main__":
    main()
