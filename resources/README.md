# Resources & References 📚

Comprehensive collection of cybersecurity resources, references, training materials, and community links to support security professionals.

## 📋 Resource Categories

### Training & Certification
- [Professional Certifications](certifications.md)
- [Online Training Platforms](training-platforms.md)
- [Hands-on Labs](practical-labs.md)
- [Academic Programs](academic-programs.md)
- [Conference & Events](conferences.md)

### Tools & Software
- [Open Source Security Tools](open-source-tools.md)
- [Commercial Security Solutions](commercial-tools.md)
- [Vulnerability Databases](vuln-databases.md)
- [Threat Intelligence Feeds](threat-intel.md)
- [Security Frameworks](frameworks.md)

### Documentation & Standards
- [Industry Standards](standards.md)
- [Compliance Frameworks](compliance.md)
- [Best Practice Guides](best-practices.md)
- [Research Papers](research.md)
- [White Papers](whitepapers.md)

### Community & Networking
- [Professional Organizations](organizations.md)
- [Online Communities](communities.md)
- [Security Blogs](blogs.md)
- [Podcasts](podcasts.md)
- [Social Media](social-media.md)

## 🎓 Essential Certifications

### Entry Level
- **CompTIA Security+**: Foundation security certification
- **CompTIA Network+**: Networking fundamentals
- **SANS GIAC Security Essentials (GSEC)**: Broad security knowledge
- **(ISC)² Systems Security Certified Practitioner (SSCP)**: Security practitioner

### Intermediate Level
- **Certified Ethical Hacker (CEH)**: Ethical hacking fundamentals
- **GCIH (GIAC Certified Incident Handler)**: Incident response
- **GCFA (GIAC Certified Forensic Analyst)**: Digital forensics
- **CISSP Associate**: Information security management

### Advanced Level
- **CISSP**: Certified Information Systems Security Professional
- **OSCP**: Offensive Security Certified Professional
- **CISM**: Certified Information Security Manager
- **CISSP**: Information systems security architecture

### Specialized Certifications
- **OSWE**: Offensive Security Web Expert
- **CRTP**: Certified Red Team Professional
- **CCSP**: Certified Cloud Security Professional
- **SANS Expert Level**: Various specialized tracks

## 🛠️ Essential Security Tools

### Network Security
```bash
# Open Source Tools
- Nmap          # Network discovery and security auditing
- Wireshark     # Network protocol analyzer
- Suricata      # Network threat detection
- pfSense       # Firewall and router platform
- Security Onion # Network security monitoring

# Installation examples
sudo apt install nmap wireshark suricata
docker run -d --name security-onion securityonion/so-standalone
```

### Vulnerability Assessment
```bash
# Scanner Tools
- OpenVAS       # Vulnerability assessment system
- Nessus        # Professional vulnerability scanner  
- Nuclei        # Template-based vulnerability scanner
- Nikto         # Web server scanner
- SQLmap        # SQL injection testing tool

# Usage examples
openvas-setup
nessus-service --start
nuclei -t templates/ -l targets.txt
```

### Penetration Testing
```bash
# Frameworks and Platforms
- Metasploit    # Exploitation framework
- Burp Suite    # Web application testing
- OWASP ZAP     # Web app security scanner
- Cobalt Strike # Adversary simulation
- Empire        # Post-exploitation framework

# Command examples
msfconsole
java -jar burpsuite_community.jar
zaproxy.sh
```

### Incident Response & Forensics
```bash
# Analysis Tools
- Volatility    # Memory forensics framework
- Autopsy       # Digital forensics platform
- TheHive       # Incident response platform
- MISP          # Threat intelligence sharing
- Sleuth Kit    # Digital investigation tools

# Usage examples
volatility -f memory.dump --profile=Win10x64 pslist
autopsy &
```

## 📖 Essential Reading Lists

### Foundational Books
- **"The Art of Deception" by Kevin Mitnick**: Social engineering fundamentals
- **"Hacking: The Art of Exploitation" by Jon Erickson**: Technical hacking concepts
- **"The Web Application Hacker's Handbook" by Stuttard & Pinto**: Web security
- **"Network Security Essentials" by William Stallings**: Network security principles
- **"Computer Security: Principles and Practice" by Stallings & Brown**: Comprehensive security

### Advanced Topics
- **"Red Team Field Manual" by Ben Clark**: Tactical reference guide
- **"Blue Team Field Manual" by Alan White**: Defensive operations
- **"The Shellcoder's Handbook" by Koziol et al.**: Advanced exploitation
- **"Malware Analyst's Cookbook" by Ligh et al.**: Malware analysis
- **"Incident Response & Computer Forensics" by Luttgens et al.**: IR procedures

### Management and Strategy
- **"CISSP Official Study Guide" by Sybex**: Security management
- **"The CISO Handbook" by Todd Fitzgerald**: Security leadership
- **"Security Risk Management" by Kaplan & Garrick**: Risk assessment
- **"The Phoenix Project" by Kim, Behr & Spafford**: DevOps and security
- **"Cybersecurity and Cyberwar" by P.W. Singer**: Strategic perspective

## 🌐 Online Learning Platforms

### Free Platforms
```markdown
# Cybrary (cybrary.it)
- Comprehensive cybersecurity courses
- Career paths and skill assessments
- Virtual labs and hands-on practice
- Community forums and networking

# SANS Cyber Aces (cyberaces.org)
- Interactive tutorials and challenges
- Operating systems security
- Web application security
- Network security fundamentals

# Coursera Security Courses
- University-level courses
- IBM Cybersecurity Analyst Professional
- Google IT Support Professional
- University of Colorado System specializations
```

### Premium Platforms
```markdown
# SANS Training (sans.org)
- Industry-leading cybersecurity training
- Hands-on lab environments
- Expert instructors
- GIAC certifications included

# Pluralsight (pluralsight.com)
- Technology skill development
- Learning paths for security roles
- Skill assessments and analytics
- Hands-on labs and projects

# Linux Academy / A Cloud Guru
- Cloud security specializations
- DevSecOps training paths
- Hands-on lab environments
- Certification preparation
```

### Practical Labs
```markdown
# Hack The Box (hackthebox.eu)
- Real-world penetration testing scenarios
- Active and retired machines
- Pro labs for advanced training
- Academy learning paths

# TryHackMe (tryhackme.com)
- Beginner-friendly security challenges
- Guided learning paths
- Virtual machine environments
- Community-driven content

# VulnHub (vulnhub.com)
- Vulnerable virtual machines
- CTF-style challenges
- Skill development focus
- Free downloadable VMs
```

## 🏛️ Professional Organizations

### International Organizations
- **(ISC)² - International Information System Security Certification Consortium**
- **ISACA - Information Systems Audit and Control Association**
- **CompTIA - Computing Technology Industry Association**
- **EC-Council - International Council of Electronic Commerce Consultants**
- **SANS Institute - SysAdmin, Audit, Network, and Security Institute**

### Regional Organizations
- **OWASP - Open Web Application Security Project**
- **FIRST - Forum of Incident Response and Security Teams**
- **ENISA - European Union Agency for Cybersecurity**
- **NIST - National Institute of Standards and Technology**
- **CISA - Cybersecurity and Infrastructure Security Agency**

### Industry-Specific Groups
- **FS-ISAC - Financial Services Information Sharing and Analysis Center**
- **HC3 - Health Sector Cybersecurity Coordination Center**
- **ICS-CERT - Industrial Control Systems Cyber Emergency Response Team**
- **Auto-ISAC - Automotive Information Sharing and Analysis Center**

## 📡 Security Conferences & Events

### Major International Conferences
```markdown
# Black Hat / DEF CON (Las Vegas, August)
- Premier security conference
- Technical presentations and training
- Vendor exhibitions and networking
- Villages and hands-on workshops

# RSA Conference (San Francisco, February/March)
- Business-focused security conference  
- Leadership and strategy content
- Technology exhibitions
- Professional networking

# BSides (Multiple locations year-round)
- Community-driven security events
- Local security communities
- Affordable and accessible
- Technical presentations and workshops
```

### Specialized Conferences
```markdown
# SANS Conferences (Multiple locations)
- Training-focused events
- Hands-on workshops
- NetWars tournaments
- Expert instructors

# (ISC)² Security Congress
- CISSP and security management focus
- Professional development
- Certification maintenance credits
- Leadership and governance topics

# OWASP Global AppSec Conferences
- Web application security focus
- Open source security tools
- Research presentations
- Developer-focused content
```

## 🎧 Security Podcasts

### Technical Podcasts
- **Security Now**: Technical security discussions
- **Darknet Diaries**: Cybercrime and hacking stories
- **Malicious Life**: Cybersecurity history and stories
- **Risky Business**: Security news and analysis
- **The CyberWire**: Daily cybersecurity news

### Business/Strategy Podcasts
- **CISO Series**: Leadership and strategy
- **Down the Security Rabbithole**: Security industry discussions
- **Application Security Podcast**: AppSec focused content
- **Cloud Security Podcast**: Cloud security topics
- **Security Ledger**: Security news and analysis

## 📰 Security News & Blogs

### News Sources
- **Krebs on Security**: Investigative cybersecurity journalism
- **The Hacker News**: Breaking security news
- **Security Week**: Enterprise security news
- **Dark Reading**: Security news and analysis
- **InfoSecurity Magazine**: Global security news

### Technical Blogs
- **Google Project Zero**: Vulnerability research
- **Microsoft Security Response Center**: Microsoft security updates
- **FireEye Threat Intelligence**: Advanced threat research
- **CrowdStrike Intelligence**: Threat hunting and analysis
- **Recorded Future**: Threat intelligence research

## 🛡️ Threat Intelligence Sources

### Commercial Feeds
- **Recorded Future**: Real-time threat intelligence
- **FireEye iSIGHT**: Advanced threat intelligence
- **CrowdStrike Falcon X**: Threat intelligence platform
- **IBM X-Force**: Security intelligence services
- **Mandiant Threat Intelligence**: APT and malware intelligence

### Open Source Intelligence
- **MISP Project**: Open source threat intelligence platform
- **OTX AlienVault**: Open threat exchange
- **ThreatMiner**: Threat intelligence search engine
- **VirusTotal**: File and URL analysis
- **Hybrid Analysis**: Automated malware analysis

### Government Sources
- **US-CERT**: United States Computer Emergency Readiness Team
- **NCSC**: National Cyber Security Centre (UK)
- **CERT-EU**: Computer Emergency Response Team for EU institutions
- **ACSC**: Australian Cyber Security Centre
- **ANSSI**: French National Cybersecurity Agency

## 📋 Compliance & Standards

### Security Frameworks
- **NIST Cybersecurity Framework**: Risk management framework
- **ISO 27001/27002**: Information security management systems
- **CIS Controls**: Critical security controls
- **COBIT**: Control Objectives for Information Technology
- **ITIL**: IT Infrastructure Library

### Industry Regulations
- **PCI DSS**: Payment Card Industry Data Security Standard
- **HIPAA**: Health Insurance Portability and Accountability Act
- **SOX**: Sarbanes-Oxley Act
- **GDPR**: General Data Protection Regulation
- **FISMA**: Federal Information Security Management Act

## 🔗 Useful Websites & Portals

### Reference Sites
- **CVE Details**: Common vulnerabilities and exposures database
- **CAPEC**: Common Attack Pattern Enumeration and Classification
- **OWASP**: Open Web Application Security Project
- **SANS Reading Room**: Security research papers
- **Security Focus**: Vulnerability database and discussions

### Tool Repositories
- **Kali Linux Tools**: Penetration testing tool collection
- **Security Tools**: Curated security tool lists
- **GitHub Security**: Open source security projects
- **PacketStorm**: Security tools and exploits
- **Exploit Database**: Public exploit archive

---

*This resource collection is continuously updated. Please contribute additional resources through our [GitHub repository](https://github.com/hailystevens/totalOps-playBook).*