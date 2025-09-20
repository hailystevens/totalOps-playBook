# Defense & Blue Team Operations 🛡️

Comprehensive defense strategies, monitoring techniques, and incident response procedures for protecting against cyber threats.

## 📋 Defense Categories

### Network Security
- [Firewall Configuration](firewall-config.md)
- [Intrusion Detection Systems (IDS)](ids-configuration.md)
- [Network Segmentation](network-segmentation.md)
- [DNS Security](dns-security.md)
- [VPN Security](vpn-security.md)

### Endpoint Protection
- [Antivirus and EDR](endpoint-protection.md)
- [Host-based Firewalls](host-firewalls.md)
- [Application Whitelisting](app-whitelisting.md)
- [Patch Management](patch-management.md)
- [System Hardening](system-hardening.md)

### Identity and Access Management
- [Active Directory Security](ad-security.md)
- [Multi-Factor Authentication](mfa-implementation.md)
- [Privileged Access Management](pam.md)
- [Identity Governance](identity-governance.md)

### Security Monitoring and SIEM
- [Log Management](log-management.md)
- [SIEM Configuration](siem-setup.md)
- [Security Analytics](security-analytics.md)
- [Threat Intelligence](threat-intelligence.md)

## 🛠️ Essential Defense Tools

### Network Security Tools
- **pfSense**: Open-source firewall and router
- **Suricata**: Network threat detection engine
- **Snort**: Open-source intrusion detection system
- **Security Onion**: Network security monitoring platform
- **Zeek**: Network analysis framework

### Endpoint Detection and Response (EDR)
- **CrowdStrike Falcon**: Cloud-native endpoint protection
- **Microsoft Defender**: Windows built-in security
- **Carbon Black**: Endpoint security platform
- **SentinelOne**: Autonomous endpoint protection
- **OSSEC**: Open-source host intrusion detection

### SIEM and Log Analysis
- **Splunk**: Data analytics and SIEM platform
- **Elastic Stack (ELK)**: Search, analytics, and visualization
- **IBM QRadar**: Security intelligence platform
- **ArcSight**: Enterprise security management
- **Graylog**: Open-source log management

### Threat Intelligence Platforms
- **MISP**: Malware information sharing platform
- **OpenCTI**: Open cyber threat intelligence platform
- **ThreatConnect**: Threat intelligence platform
- **Anomali**: Threat intelligence management
- **ThreatQ**: Threat intelligence platform

## 📝 Defense-in-Depth Strategy

### 1. Perimeter Security
```bash
# Firewall rule examples (iptables)
# Block all incoming traffic by default
iptables -P INPUT DROP
iptables -P FORWARD DROP

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow specific services
iptables -A INPUT -p tcp --dport 22 -s trusted-ip -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

### 2. Network Monitoring
```bash
# Suricata configuration
# Enable detection modes
detection-engine:
  - profile: medium
  - custom-values:
      toclient-groups: 3
      toserver-groups: 25

# Zeek monitoring setup
/usr/local/zeek/bin/zeek -i eth0 local
tail -f /usr/local/zeek/logs/current/conn.log
```

### 3. Endpoint Hardening
```bash
# Windows hardening examples
# Disable unnecessary services
sc config "RemoteAccess" start= disabled
sc config "Fax" start= disabled

# Enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
```

### 4. Access Control Implementation
```powershell
# Active Directory security
# Enable advanced auditing
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable

# Implement least privilege
Add-ADGroupMember -Identity "Limited Users" -Members "username"
Remove-ADGroupMember -Identity "Domain Admins" -Members "username"
```

## 🔍 Threat Detection and Hunting

### Detection Rules and Signatures
```yaml
# Suricata rule example
alert tcp any any -> $HOME_NET any (
    msg:"Potential malware C2 communication";
    flow:established,to_server;
    content:"User-Agent|3a| ";
    content:"Mozilla/4.0";
    sid:1000001;
    rev:1;
)
```

### YARA Rules for Malware Detection
```yara
rule Suspicious_PowerShell_Script
{
    meta:
        description = "Detects suspicious PowerShell commands"
        author = "Blue Team"
        date = "2025-01-01"
    
    strings:
        $a = "Invoke-Expression" nocase
        $b = "DownloadString" nocase
        $c = "System.Net.WebClient" nocase
        $d = "-ExecutionPolicy Bypass" nocase
    
    condition:
        2 of them
}
```

### Sigma Rules for SIEM
```yaml
title: Suspicious Process Creation
description: Detects suspicious process execution
status: experimental
references:
    - https://attack.mitre.org/techniques/T1059/
tags:
    - attack.execution
    - attack.t1059
detection:
    selection:
        EventID: 4688
        NewProcessName|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'DownloadString'
    condition: selection
```

## 📊 Security Metrics and KPIs

### Key Performance Indicators
- **Mean Time to Detection (MTTD)**: Average time to identify threats
- **Mean Time to Response (MTTR)**: Average time to respond to incidents
- **False Positive Rate**: Percentage of false security alerts
- **Security Coverage**: Percentage of assets monitored
- **Vulnerability Exposure Time**: Time vulnerabilities remain unpatched

### Monitoring Dashboards
```bash
# Splunk dashboard queries
# Failed login attempts
index=security EventCode=4625 | stats count by src_ip | sort -count

# Suspicious process executions
index=sysmon EventCode=1 CommandLine="*powershell*" | stats count by Computer

# Network anomalies
index=network | stats avg(bytes_out) by src_ip | where avg(bytes_out) > 1000000
```

## 🚨 Incident Response Integration

### Automated Response Workflows
```python
# SOAR playbook example (Phantom/Splunk)
def investigate_suspicious_login(container, results, handle):
    # Block suspicious IP
    phantom.act("block ip", parameters=[{"ip": suspicious_ip}])
    
    # Disable user account
    phantom.act("disable user", parameters=[{"username": username}])
    
    # Collect additional forensic data
    phantom.act("get system info", parameters=[{"ip": target_system}])
```

### Threat Hunting Queries
```sql
-- SQL query for threat hunting (Splunk/Elasticsearch)
-- Detect lateral movement via SMB
SELECT 
    src_ip, 
    dest_ip, 
    user, 
    COUNT(*) as connection_count
FROM network_logs 
WHERE 
    port = 445 
    AND protocol = 'SMB'
    AND timestamp > NOW() - INTERVAL 1 HOUR
GROUP BY src_ip, dest_ip, user
HAVING connection_count > 10;
```

## 🔧 Security Automation and Orchestration

### SOAR (Security Orchestration, Automation, and Response)
- **Phantom (Splunk)**: Enterprise SOAR platform
- **Demisto (Palo Alto)**: Security orchestration platform
- **TheHive**: Open-source incident response platform
- **MISP**: Threat intelligence sharing platform
- **Cortex**: Observable analysis and active response

### Security Automation Scripts
```python
# Automated threat response script
import requests
import json

def block_malicious_ip(ip_address):
    # Update firewall rules
    firewall_api = "https://firewall.company.com/api/block"
    payload = {"ip": ip_address, "action": "block"}
    
    response = requests.post(firewall_api, json=payload)
    
    if response.status_code == 200:
        print(f"Successfully blocked {ip_address}")
        # Update threat intelligence database
        update_threat_intel(ip_address)
    else:
        print(f"Failed to block {ip_address}")

def update_threat_intel(ioc):
    # Add IOC to threat intelligence platform
    misp_api = "https://misp.company.com/attributes/add"
    headers = {"Authorization": "Bearer api-key"}
    
    ioc_data = {
        "type": "ip-dst",
        "value": ioc,
        "category": "Network activity",
        "to_ids": True
    }
    
    requests.post(misp_api, headers=headers, json=ioc_data)
```

## 🛡️ Hardening Guidelines

### Operating System Hardening
```bash
# Linux hardening checklist
# Disable unnecessary services
systemctl disable telnet
systemctl disable ftp
systemctl disable rsh

# Set proper file permissions
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 600 /boot/grub/grub.cfg

# Enable firewall
ufw enable
ufw default deny incoming
ufw default allow outgoing
```

### Network Hardening
```bash
# Network security settings
# Disable IP forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward

# Enable SYN flood protection
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Disable ICMP redirects
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
```

### Application Hardening
```bash
# Web server hardening (Apache/Nginx)
# Hide server version
ServerTokens Prod
ServerSignature Off

# Security headers
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
Header always set X-XSS-Protection "1; mode=block"
```

## 📚 Defense Frameworks and Standards

### Security Frameworks
- **NIST Cybersecurity Framework**: Identify, Protect, Detect, Respond, Recover
- **ISO 27001**: Information security management systems
- **CIS Controls**: Critical security controls
- **SANS Top 20**: Critical security controls
- **MITRE ATT&CK**: Adversarial tactics and techniques

### Compliance Standards
- **PCI DSS**: Payment card industry data security
- **HIPAA**: Healthcare information protection
- **SOX**: Financial reporting controls
- **GDPR**: General data protection regulation
- **FISMA**: Federal information security management

## 🎓 Blue Team Training

### Recommended Certifications
- **GCIH**: GIAC Certified Incident Handler
- **GSEC**: GIAC Security Essentials
- **GCFA**: GIAC Certified Forensic Analyst
- **CISSP**: Certified Information Systems Security Professional
- **CCSP**: Certified Cloud Security Professional

### Training Platforms
- **SANS**: Industry-leading cybersecurity training
- **Cybrary**: Free cybersecurity training
- **Blue Team Labs Online**: Hands-on blue team training
- **LetsDefend**: SOC analyst training platform
- **Attack Defense**: Enterprise security training

### Practice Environments
- **Detection Lab**: Windows domain for detection testing
- **Security Blue Team**: Blue team training platform
- **Immersive Labs**: Cybersecurity skills platform
- **RangeForce**: Cyber range training platform