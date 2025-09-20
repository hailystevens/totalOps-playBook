# Incident Response Playbooks 🚨

Comprehensive incident response procedures, playbooks, and tools for handling cybersecurity incidents effectively.

## 📋 Incident Categories

### Malware Incidents
- [Malware Analysis](malware/malware-analysis.md)
- [Ransomware Response](malware/ransomware-response.md)
- [APT Incident Handling](malware/apt-response.md)
- [Cryptocurrency Mining](malware/cryptomining.md)

### Network Incidents
- [Network Intrusion](network/network-intrusion.md)
- [DDoS Attack Response](network/ddos-response.md)
- [Data Exfiltration](network/data-exfiltration.md)
- [Lateral Movement](network/lateral-movement.md)

### System Compromises
- [Server Compromise](systems/server-compromise.md)
- [Endpoint Compromise](systems/endpoint-compromise.md)
- [Privilege Escalation](systems/privilege-escalation.md)
- [Persistence Mechanisms](systems/persistence.md)

### Data Incidents
- [Data Breach Response](data/data-breach.md)
- [Insider Threat](data/insider-threat.md)
- [Accidental Exposure](data/accidental-exposure.md)
- [Cloud Data Incidents](data/cloud-incidents.md)

## 🎯 Incident Response Framework (NIST)

### 1. Preparation
- Incident response team establishment
- Policies and procedures development
- Tools and technology deployment
- Training and awareness programs
- Communication plans

### 2. Detection and Analysis
- Event monitoring and alerting
- Incident classification and prioritization
- Initial assessment and scoping
- Evidence collection and preservation
- Root cause analysis

### 3. Containment, Eradication, and Recovery
- Immediate containment actions
- System isolation and quarantine
- Threat eradication procedures
- System recovery and restoration
- Business continuity measures

### 4. Post-Incident Activity
- Lessons learned documentation
- Process improvement recommendations
- Legal and regulatory reporting
- Stakeholder communication
- Timeline and cost analysis

## 🚨 General Incident Response Playbook

### Phase 1: Initial Response (0-1 Hour)
```bash
# Immediate Actions Checklist
□ Confirm incident validity
□ Assess initial scope and impact
□ Notify incident response team
□ Begin documentation (incident log)
□ Implement initial containment if safe
□ Preserve volatile evidence
□ Establish communication channels
```

### Phase 2: Assessment and Containment (1-4 Hours)
```bash
# Assessment Actions
# Network traffic analysis
tcpdump -i eth0 -w incident_capture.pcap
netstat -tulpn > network_connections.txt

# System process analysis
ps aux > running_processes.txt
lsof > open_files.txt

# Memory capture (if possible)
dd if=/dev/mem of=memory_dump.img bs=1MB

# Disk imaging
dd if=/dev/sda of=/mnt/evidence/disk_image.img bs=512 conv=noerror,sync
```

### Phase 3: Deep Analysis (4-24 Hours)
```python
# Log analysis script example
import re
import datetime

def analyze_security_logs(log_file):
    """Analyze security logs for indicators of compromise."""
    indicators = {
        'suspicious_ips': [],
        'malicious_processes': [],
        'unusual_network_activity': [],
        'privilege_escalations': []
    }
    
    with open(log_file, 'r') as f:
        for line in f:
            # Check for suspicious IP patterns
            if re.search(r'failed login.*from (\d+\.\d+\.\d+\.\d+)', line):
                ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line).group(1)
                indicators['suspicious_ips'].append(ip)
            
            # Check for privilege escalation
            if 'sudo' in line and 'root' in line:
                indicators['privilege_escalations'].append(line.strip())
    
    return indicators
```

## 🔍 Digital Forensics Integration

### Evidence Collection Procedures
```bash
# Create forensic image with verification
dd if=/dev/sda conv=sync,noerror bs=64K | tee disk_image.dd | sha256sum > image_hash.txt

# Collect volatile data
echo "=== System Information ===" > volatile_data.txt
uname -a >> volatile_data.txt
date >> volatile_data.txt
uptime >> volatile_data.txt

echo "=== Network Connections ===" >> volatile_data.txt
netstat -tulpn >> volatile_data.txt
ss -tulpn >> volatile_data.txt

echo "=== Running Processes ===" >> volatile_data.txt
ps auxwwf >> volatile_data.txt

echo "=== Open Files ===" >> volatile_data.txt
lsof >> volatile_data.txt

echo "=== Loaded Modules ===" >> volatile_data.txt
lsmod >> volatile_data.txt

# Hash calculation for evidence integrity
find /path/to/evidence -type f -exec sha256sum {} \; > evidence_hashes.txt
```

### Chain of Custody Documentation
```markdown
# Chain of Custody Form

**Incident ID**: INC-2025-001
**Evidence Item**: Server hard drive - /dev/sda
**Serial Number**: WD-ABC123456789
**Collection Date**: 2025-01-20 14:30:00 UTC
**Collected By**: John Doe, CISSP
**Location**: Data Center Room 101

## Custody Transfer Log
| Date/Time | From | To | Purpose | Signature |
|-----------|------|----|---------| --------- |
| 2025-01-20 14:30 | Scene | J. Doe | Collection | JDoe |
| 2025-01-20 16:45 | J. Doe | Lab | Analysis | JDoe |
```

## 📊 Incident Classification Matrix

### Severity Levels
```
Critical (P1): System compromise with data loss/exposure
High (P2): Confirmed malware or unauthorized access
Medium (P3): Suspicious activity requiring investigation
Low (P4): Policy violations or minor security events
```

### Impact Assessment
- **Confidentiality**: Data exposure risk
- **Integrity**: Data modification risk  
- **Availability**: Service disruption risk
- **Business Impact**: Financial and operational impact
- **Regulatory**: Compliance and legal implications

## 🛠️ Incident Response Tools

### Open Source Tools
- **TheHive**: Case management platform
- **Cortex**: Observable analysis engine
- **MISP**: Threat intelligence sharing
- **Volatility**: Memory forensics framework
- **Autopsy**: Digital forensics platform

### Commercial Tools
- **Splunk Phantom**: SOAR platform
- **IBM Resilient**: Incident response platform
- **FireEye Helix**: Security operations platform
- **CrowdStrike Falcon**: Endpoint detection and response
- **Palo Alto Cortex XSOAR**: Security orchestration

### Custom Scripts and Utilities
```python
# Incident response automation script
import subprocess
import datetime
import json

class IncidentResponse:
    def __init__(self, incident_id):
        self.incident_id = incident_id
        self.start_time = datetime.datetime.now()
        self.evidence_dir = f"/incidents/{incident_id}/evidence"
        self.log_file = f"/incidents/{incident_id}/incident.log"
    
    def collect_system_info(self):
        """Collect basic system information."""
        commands = {
            'uname': 'uname -a',
            'processes': 'ps auxwwf',
            'network': 'netstat -tulpn',
            'files': 'lsof',
            'users': 'who'
        }
        
        results = {}
        for name, cmd in commands.items():
            try:
                result = subprocess.run(cmd.split(), 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=30)
                results[name] = result.stdout
            except Exception as e:
                results[name] = f"Error: {str(e)}"
        
        return results
    
    def create_timeline(self, events):
        """Create incident timeline."""
        timeline = []
        for event in events:
            timeline.append({
                'timestamp': event['timestamp'],
                'source': event['source'],
                'description': event['description'],
                'severity': event.get('severity', 'medium')
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        return timeline
```

## 📋 Incident Response Checklists

### Malware Incident Checklist
```markdown
## Initial Response (0-30 minutes)
- [ ] Identify affected systems
- [ ] Isolate infected systems from network
- [ ] Preserve system state (memory dump if possible)
- [ ] Document initial findings
- [ ] Notify stakeholders

## Analysis Phase (30 minutes - 4 hours)
- [ ] Collect malware samples
- [ ] Analyze malware behavior
- [ ] Identify indicators of compromise (IOCs)
- [ ] Determine attack vector
- [ ] Assess damage and data exposure

## Containment and Eradication (4-24 hours)
- [ ] Remove malware from all affected systems
- [ ] Patch vulnerabilities exploited
- [ ] Update security controls
- [ ] Implement additional monitoring
- [ ] Verify successful eradication

## Recovery and Monitoring (24+ hours)
- [ ] Restore systems from clean backups
- [ ] Implement enhanced monitoring
- [ ] Update incident response procedures
- [ ] Conduct lessons learned session
- [ ] Update threat intelligence
```

### Data Breach Response Checklist
```markdown
## Immediate Response (0-1 hour)
- [ ] Confirm data breach has occurred
- [ ] Identify type and scope of data involved
- [ ] Contain the breach source
- [ ] Preserve evidence
- [ ] Activate incident response team

## Assessment Phase (1-24 hours)
- [ ] Determine root cause of breach
- [ ] Assess data sensitivity and volume
- [ ] Identify affected individuals/customers
- [ ] Evaluate regulatory requirements
- [ ] Document timeline of events

## Notification Phase (24-72 hours)
- [ ] Notify law enforcement (if required)
- [ ] Report to regulatory authorities
- [ ] Inform affected individuals
- [ ] Coordinate with legal team
- [ ] Prepare public communications

## Remediation Phase (Ongoing)
- [ ] Implement security improvements
- [ ] Monitor for additional exposure
- [ ] Provide identity protection services
- [ ] Update policies and procedures
- [ ] Conduct post-incident review
```

## 📞 Communication Templates

### Internal Incident Notification
```
SUBJECT: SECURITY INCIDENT - [SEVERITY] - [INCIDENT-ID]

INCIDENT SUMMARY:
- Incident ID: INC-2025-001
- Severity: High
- Discovery Time: 2025-01-20 09:15 UTC
- Status: Under Investigation

INITIAL ASSESSMENT:
- Affected Systems: [List systems]
- Potential Impact: [Brief description]
- Indicators: [Key IOCs]

IMMEDIATE ACTIONS TAKEN:
- [Action 1]
- [Action 2]
- [Action 3]

NEXT STEPS:
- [Next action]
- [Timeline]

CONTACT INFORMATION:
- Incident Commander: [Name, Phone, Email]
- Technical Lead: [Name, Phone, Email]
```

### External Breach Notification
```
Dear [Customer/Stakeholder],

We are writing to inform you of a security incident that may have affected your personal information. On [DATE], we discovered unauthorized access to our systems containing customer data.

WHAT HAPPENED:
[Brief description of the incident]

INFORMATION INVOLVED:
[Types of data potentially accessed]

WHAT WE ARE DOING:
- Immediately secured the affected systems
- Launched comprehensive investigation
- Notified law enforcement and regulators
- Implemented additional security measures

WHAT YOU CAN DO:
[Recommended protective actions]

We sincerely apologize for this incident and any inconvenience it may cause.

Contact Information: [Phone, Email, Website]
```

## 🎓 Training and Certification

### Incident Response Certifications
- **GCIH**: GIAC Certified Incident Handler
- **GCFA**: GIAC Certified Forensic Analyst  
- **GNFA**: GIAC Network Forensic Analyst
- **CISSP**: Certified Information Systems Security Professional
- **CISM**: Certified Information Security Manager

### Training Resources
- **SANS Institute**: Incident handling and forensics courses
- **EC-Council**: Computer hacking forensic investigator
- **NIST**: Computer security incident handling guide
- **ENISA**: Incident response training materials