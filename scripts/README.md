# Automation Scripts & Utilities 🔧

Collection of automation scripts, utilities, and tools for cybersecurity operations, incident response, and security testing.

## 📋 Script Categories

### Network Security Scripts
- [Port Scanner](network/port-scanner.py)
- [Network Discovery](network/network-discovery.sh)
- [SSL Certificate Checker](network/ssl-checker.py)
- [DNS Enumeration](network/dns-enum.py)
- [Bandwidth Monitor](network/bandwidth-monitor.sh)

### System Administration
- [Log Analyzer](sysadmin/log-analyzer.py)
- [User Audit](sysadmin/user-audit.sh)
- [System Hardening](sysadmin/hardening-script.sh)
- [Backup Verification](sysadmin/backup-verify.py)
- [Service Monitor](sysadmin/service-monitor.sh)

### Incident Response
- [Memory Dump Analyzer](incident-response/memory-analysis.py)
- [IOC Extractor](incident-response/ioc-extractor.py)
- [Timeline Generator](incident-response/timeline-gen.py)
- [Artifact Collector](incident-response/artifact-collector.sh)
- [Hash Calculator](incident-response/hash-calculator.py)

### Vulnerability Management
- [CVE Checker](vuln-mgmt/cve-checker.py)
- [Patch Status](vuln-mgmt/patch-status.sh)
- [Vulnerability Scanner](vuln-mgmt/vuln-scanner.py)
- [Report Generator](vuln-mgmt/report-generator.py)

## 🐍 Python Scripts

### Network Port Scanner
```python
#!/usr/bin/env python3
"""
Simple multi-threaded port scanner
Usage: python3 port_scanner.py <target> <start_port> <end_port>
"""
import socket
import threading
import sys
from datetime import datetime

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port}: Open")
        sock.close()
    except socket.gaierror:
        pass

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 port_scanner.py <target> <start_port> <end_port>")
        sys.exit(1)
    
    target = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    
    print(f"Scanning {target} from port {start_port} to {end_port}")
    print(f"Starting scan at {datetime.now()}")
    
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    print(f"Scan completed at {datetime.now()}")

if __name__ == "__main__":
    main()
```

### Log Analysis Script
```python
#!/usr/bin/env python3
"""
Security log analyzer for common attack patterns
"""
import re
import sys
from collections import Counter
from datetime import datetime

def analyze_log_file(filename):
    suspicious_patterns = {
        'sql_injection': r'(union|select|insert|delete|drop|exec|script)',
        'xss_attempts': r'(<script|javascript:|onload=|onerror=)',
        'directory_traversal': r'(\.\./|\.\.\\|/etc/passwd|/windows/system32)',
        'brute_force': r'(failed login|authentication failed|invalid user)',
        'command_injection': r'(;|\||&|`|\$\()'
    }
    
    results = {pattern: [] for pattern in suspicious_patterns}
    ip_counter = Counter()
    
    with open(filename, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line_lower = line.lower()
            
            # Extract IP addresses
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            if ip_match:
                ip_counter[ip_match.group()] += 1
            
            # Check for suspicious patterns
            for pattern_name, pattern in suspicious_patterns.items():
                if re.search(pattern, line_lower):
                    results[pattern_name].append((line_num, line.strip()))
    
    # Generate report
    print("=== Security Log Analysis Report ===")
    print(f"Analyzed file: {filename}")
    print(f"Analysis time: {datetime.now()}")
    print()
    
    for pattern_name, matches in results.items():
        if matches:
            print(f"{pattern_name.upper()} - {len(matches)} occurrences:")
            for line_num, line in matches[:5]:  # Show first 5 matches
                print(f"  Line {line_num}: {line[:100]}...")
            print()
    
    print("Top 10 IP addresses by frequency:")
    for ip, count in ip_counter.most_common(10):
        print(f"  {ip}: {count} requests")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 log_analyzer.py <log_file>")
        sys.exit(1)
    
    analyze_log_file(sys.argv[1])
```

## 🔨 Bash Scripts

### System Hardening Script
```bash
#!/bin/bash
# Linux system hardening script
# Run with sudo privileges

echo "Starting system hardening..."

# Update system packages
apt update && apt upgrade -y

# Install security tools
apt install -y fail2ban ufw rkhunter chkrootkit

# Configure firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw --force enable

# Configure fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Secure SSH configuration
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# Set proper file permissions
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 600 /boot/grub/grub.cfg

# Disable unnecessary services
systemctl disable telnet
systemctl disable ftp
systemctl disable rsh

# Enable process accounting
apt install -y acct
systemctl enable acct

# Configure automatic updates
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

echo "System hardening completed!"
```

### Network Discovery Script
```bash
#!/bin/bash
# Network discovery and enumeration script

if [ $# -ne 1 ]; then
    echo "Usage: $0 <network_range>"
    echo "Example: $0 192.168.1.0/24"
    exit 1
fi

NETWORK=$1
OUTPUT_DIR="network_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "Starting network discovery for $NETWORK"
echo "Results will be saved in $OUTPUT_DIR"

# Host discovery
echo "Performing host discovery..."
nmap -sn $NETWORK > $OUTPUT_DIR/host_discovery.txt

# Extract live hosts
LIVE_HOSTS=$(grep "Nmap scan report" $OUTPUT_DIR/host_discovery.txt | awk '{print $5}')

# Port scanning for live hosts
echo "Performing port scans on live hosts..."
for host in $LIVE_HOSTS; do
    echo "Scanning $host..."
    nmap -sV -sC $host > $OUTPUT_DIR/scan_$host.txt
done

# Service enumeration
echo "Performing service enumeration..."
nmap -sV --script=banner,http-title,smb-os-discovery $NETWORK > $OUTPUT_DIR/service_enum.txt

# Generate summary report
echo "Generating summary report..."
{
    echo "Network Discovery Report"
    echo "======================="
    echo "Network: $NETWORK"
    echo "Scan Date: $(date)"
    echo ""
    echo "Live Hosts:"
    echo "$LIVE_HOSTS"
    echo ""
    echo "Open Ports Summary:"
    grep -h "open" $OUTPUT_DIR/scan_*.txt | sort | uniq -c | sort -nr
} > $OUTPUT_DIR/summary_report.txt

echo "Network discovery completed. Results saved in $OUTPUT_DIR"
```

## 🔍 PowerShell Scripts

### Windows Event Log Analyzer
```powershell
# Windows Security Event Log Analyzer
param(
    [string]$LogName = "Security",
    [int]$Hours = 24,
    [string]$OutputPath = "security_analysis.txt"
)

Write-Host "Analyzing Windows Event Logs..." -ForegroundColor Green

# Define suspicious event IDs
$SuspiciousEvents = @{
    4625 = "Failed logon attempt"
    4648 = "Logon using explicit credentials"
    4672 = "Special privileges assigned"
    4720 = "User account created"
    4732 = "User added to security-enabled local group"
    4756 = "User added to security-enabled universal group"
}

$StartTime = (Get-Date).AddHours(-$Hours)
$Results = @()

foreach ($EventID in $SuspiciousEvents.Keys) {
    Write-Host "Checking for Event ID $EventID..." -ForegroundColor Yellow
    
    $Events = Get-WinEvent -FilterHashtable @{
        LogName = $LogName
        ID = $EventID
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue
    
    if ($Events) {
        $Results += [PSCustomObject]@{
            EventID = $EventID
            Description = $SuspiciousEvents[$EventID]
            Count = $Events.Count
            LatestEvent = $Events[0].TimeCreated
        }
    }
}

# Generate report
$Report = @"
Windows Security Event Analysis Report
======================================
Analysis Period: Last $Hours hours
Generated: $(Get-Date)

Suspicious Activity Summary:
"@

$Results | ForEach-Object {
    $Report += "`nEvent ID $($_.EventID) - $($_.Description): $($_.Count) occurrences"
    $Report += "`n  Latest occurrence: $($_.LatestEvent)"
}

$Report | Out-File $OutputPath
Write-Host "Report saved to $OutputPath" -ForegroundColor Green
```

## 🛠️ Utility Scripts

### Hash Calculator and File Integrity Checker
```python
#!/usr/bin/env python3
"""
File integrity checker using multiple hash algorithms
"""
import hashlib
import os
import sys
import json
from datetime import datetime

def calculate_hashes(filename):
    """Calculate multiple hashes for a file."""
    hashes = {}
    hash_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    
    try:
        with open(filename, 'rb') as f:
            data = f.read()
            
        for algorithm in hash_algorithms:
            hash_obj = hashlib.new(algorithm)
            hash_obj.update(data)
            hashes[algorithm] = hash_obj.hexdigest()
            
    except Exception as e:
        print(f"Error calculating hashes for {filename}: {e}")
        return None
    
    return hashes

def create_baseline(directory, baseline_file):
    """Create baseline hash database for directory."""
    baseline = {}
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            relative_path = os.path.relpath(filepath, directory)
            
            print(f"Processing: {relative_path}")
            hashes = calculate_hashes(filepath)
            
            if hashes:
                baseline[relative_path] = {
                    'hashes': hashes,
                    'size': os.path.getsize(filepath),
                    'modified': os.path.getmtime(filepath)
                }
    
    baseline['metadata'] = {
        'created': datetime.now().isoformat(),
        'directory': directory,
        'file_count': len(baseline) - 1
    }
    
    with open(baseline_file, 'w') as f:
        json.dump(baseline, f, indent=2)
    
    print(f"Baseline created: {baseline_file}")

def check_integrity(directory, baseline_file):
    """Check file integrity against baseline."""
    try:
        with open(baseline_file, 'r') as f:
            baseline = json.load(f)
    except Exception as e:
        print(f"Error loading baseline: {e}")
        return
    
    changes = {
        'modified': [],
        'added': [],
        'deleted': []
    }
    
    current_files = set()
    
    # Check existing files
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            relative_path = os.path.relpath(filepath, directory)
            current_files.add(relative_path)
            
            if relative_path in baseline and relative_path != 'metadata':
                # File exists in baseline
                current_hashes = calculate_hashes(filepath)
                baseline_hashes = baseline[relative_path]['hashes']
                
                if current_hashes['sha256'] != baseline_hashes['sha256']:
                    changes['modified'].append(relative_path)
            else:
                # New file
                changes['added'].append(relative_path)
    
    # Check for deleted files
    baseline_files = set(baseline.keys()) - {'metadata'}
    for file in baseline_files:
        if file not in current_files:
            changes['deleted'].append(file)
    
    # Generate report
    print("\n=== File Integrity Check Report ===")
    print(f"Baseline: {baseline_file}")
    print(f"Check time: {datetime.now()}")
    print(f"Directory: {directory}")
    
    if changes['modified']:
        print(f"\nModified files ({len(changes['modified'])}):")
        for file in changes['modified']:
            print(f"  - {file}")
    
    if changes['added']:
        print(f"\nAdded files ({len(changes['added'])}):")
        for file in changes['added']:
            print(f"  + {file}")
    
    if changes['deleted']:
        print(f"\nDeleted files ({len(changes['deleted'])}):")
        for file in changes['deleted']:
            print(f"  - {file}")
    
    if not any(changes.values()):
        print("\nNo changes detected - integrity verified!")

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  Create baseline: python3 integrity_checker.py create <directory> <baseline_file>")
        print("  Check integrity: python3 integrity_checker.py check <directory> <baseline_file>")
        sys.exit(1)
    
    action = sys.argv[1]
    directory = sys.argv[2]
    baseline_file = sys.argv[3] if len(sys.argv) > 3 else "baseline.json"
    
    if action == "create":
        create_baseline(directory, baseline_file)
    elif action == "check":
        check_integrity(directory, baseline_file)
    else:
        print("Invalid action. Use 'create' or 'check'")

if __name__ == "__main__":
    main()
```

## 📊 Monitoring and Alerting Scripts

### CPU and Memory Monitor
```bash
#!/bin/bash
# System resource monitor with alerting

ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEM=85
LOG_FILE="/var/log/system_monitor.log"
EMAIL_ALERT="admin@company.com"

while true; do
    # Get system metrics
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    MEM_USAGE=$(free | grep Mem | awk '{printf("%.2f", ($3/$2)*100)}')
    DISK_USAGE=$(df -h / | awk 'NR==2{print $5}' | cut -d'%' -f1)
    
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log metrics
    echo "$TIMESTAMP - CPU: ${CPU_USAGE}%, Memory: ${MEM_USAGE}%, Disk: ${DISK_USAGE}%" >> $LOG_FILE
    
    # Check thresholds and send alerts
    if (( $(echo "$CPU_USAGE > $ALERT_THRESHOLD_CPU" | bc -l) )); then
        echo "ALERT: High CPU usage detected: ${CPU_USAGE}%" | mail -s "CPU Alert" $EMAIL_ALERT
    fi
    
    if (( $(echo "$MEM_USAGE > $ALERT_THRESHOLD_MEM" | bc -l) )); then
        echo "ALERT: High memory usage detected: ${MEM_USAGE}%" | mail -s "Memory Alert" $EMAIL_ALERT
    fi
    
    # Wait 5 minutes before next check
    sleep 300
done
```

## 🎯 Installation and Usage

### Prerequisites
```bash
# Python dependencies
pip3 install requests hashlib threading

# System tools
sudo apt install nmap netcat-openbsd whois dig

# PowerShell (for Windows-specific scripts)
# Install PowerShell Core for cross-platform usage
```

### Script Permissions
```bash
# Make scripts executable
chmod +x *.sh
chmod +x *.py

# Set appropriate ownership
chown root:root hardening-script.sh
chmod 700 hardening-script.sh
```

## 📚 Best Practices

### Script Security
- Always validate input parameters
- Use proper error handling
- Log all activities
- Follow principle of least privilege
- Regular code reviews and updates

### Documentation
- Include usage examples
- Document required permissions
- Explain potential security implications
- Provide troubleshooting guides
- Maintain change logs