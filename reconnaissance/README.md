# Reconnaissance & OSINT 🔍

This directory contains tools, techniques, and methodologies for information gathering and Open Source Intelligence (OSINT) activities.

## 📋 Categories

### Passive Reconnaissance
- [Domain & Subdomain Enumeration](domain-enumeration.md)
- [Email Harvesting](email-harvesting.md)
- [Social Media Intelligence](social-media-intel.md)
- [Search Engine Exploitation](search-engines.md)
- [Public Records & Databases](public-records.md)

### Active Reconnaissance
- [Port Scanning](port-scanning.md)
- [Service Enumeration](service-enumeration.md)
- [Web Application Discovery](web-discovery.md)
- [Network Mapping](network-mapping.md)

## 🛠️ Essential Tools

### Domain & DNS Analysis
- **whois**: Domain registration information
- **dig**: DNS lookup utility
- **nslookup**: DNS query tool
- **dnsrecon**: DNS enumeration script
- **fierce**: Domain scanner
- **sublist3r**: Subdomain enumeration tool
- **amass**: Attack surface mapping
- **subfinder**: Passive subdomain discovery

### Network Discovery
- **nmap**: Network exploration and security auditing
- **masscan**: High-speed port scanner
- **zmap**: Internet-wide scanning
- **rustscan**: Modern port scanner

### Web Reconnaissance
- **gobuster**: Directory/file brute-forcer
- **dirb**: Web content scanner
- **dirbuster**: GUI directory brute-forcer
- **wfuzz**: Web application fuzzer
- **nikto**: Web server scanner

### OSINT Frameworks
- **recon-ng**: Web reconnaissance framework
- **theHarvester**: Email, subdomain, and people enumeration
- **maltego**: Link analysis and data mining
- **spiderfoot**: OSINT automation platform
- **shodan**: Internet-connected device search engine

## 📝 Methodology

### 1. Initial Target Assessment
```bash
# Basic domain information
whois target.com
dig target.com ANY
nslookup target.com

# Check for subdomains
sublist3r -d target.com
amass enum -d target.com
```

### 2. Network Discovery
```bash
# Port scanning
nmap -sS -A -T4 target.com
masscan -p1-65535 target.com --rate=1000

# Service enumeration
nmap -sV -sC target.com
```

### 3. Web Application Discovery
```bash
# Directory enumeration
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
dirb http://target.com

# Technology stack identification
whatweb target.com
wappalyzer target.com
```

### 4. Email and People Search
```bash
# Email harvesting
theHarvester -d target.com -b google,bing,linkedin
hunter.io API integration

# Social media enumeration
sherlock username
social-analyzer --username target_user
```

## 🎯 Common Targets

### Information Sources
- Company websites and subdomains
- Social media profiles (LinkedIn, Twitter, Facebook)
- Job postings and employee directories
- Public documents and presentations
- Code repositories (GitHub, GitLab)
- DNS records and certificates
- Archive.org (Wayback Machine)
- Pastebin and code sharing sites

### Technical Infrastructure
- Domain registrations and DNS records
- SSL/TLS certificates
- Network ranges and IP addresses
- Email servers and configurations
- Cloud services and S3 buckets
- Content delivery networks (CDNs)

## 🔐 Operational Security

### Best Practices
- Use VPNs and proxy chains for anonymity
- Rotate IP addresses and user agents
- Implement request throttling and delays
- Use multiple data sources for verification
- Maintain detailed documentation of findings

### Legal Considerations
- Only gather publicly available information
- Respect robots.txt and terms of service
- Avoid aggressive scanning techniques
- Document authorization and scope
- Follow responsible disclosure practices

## 📚 Additional Resources

### Wordlists
- SecLists: Collection of security testing lists
- FuzzDB: Attack pattern and discovery database
- PayloadsAllTheThings: Web application security payloads

### Online Tools
- Shodan: Internet-connected device search
- Censys: Certificate and device discovery
- VirusTotal: File and URL analysis
- Have I Been Pwned: Breach data search
- Google Dorking: Advanced search operators

### Training Materials
- OSINT Framework: Curated list of OSINT tools
- Bellingcat's Online Investigation Toolkit
- SANS SEC487: Open-Source Intelligence Course