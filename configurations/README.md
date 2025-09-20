# Security Configurations & Hardening 🔧

Collection of security configurations, hardening guides, and baseline settings for various systems, applications, and services.

## 📋 Configuration Categories

### Operating Systems
- [Windows Hardening](windows/README.md)
- [Linux Hardening](linux/README.md)
- [macOS Security](macos/README.md)
- [VMware/Hypervisor Security](virtualization/README.md)

### Network Infrastructure
- [Firewall Configurations](network/firewalls.md)
- [Router Security](network/routers.md)
- [Switch Security](network/switches.md)
- [VPN Configurations](network/vpn.md)
- [DNS Security](network/dns.md)

### Applications & Services
- [Web Server Hardening](applications/web-servers.md)
- [Database Security](applications/databases.md)
- [Email Security](applications/email.md)
- [Active Directory](applications/active-directory.md)
- [Cloud Services](applications/cloud.md)

### Security Tools
- [SIEM Configurations](security-tools/siem.md)
- [IDS/IPS Setup](security-tools/ids-ips.md)
- [Endpoint Protection](security-tools/endpoint.md)
- [Vulnerability Scanners](security-tools/scanners.md)

## 🖥️ Windows Security Hardening

### Local Security Policy
```powershell
# Account Policies - Password Policy
secedit /configure /db %windir%\security\local.sdb /cfg password_policy.inf

# Password Policy Configuration (password_policy.inf)
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 12
RequireLogonToChangePassword = 0
ClearTextPassword = 0

# Account Lockout Policy
[System Access]
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
```

### Windows Services Hardening
```powershell
# Disable unnecessary services
$services = @(
    "Fax",
    "RemoteAccess", 
    "RemoteRegistry",
    "Spooler",
    "Telnet",
    "SNMP"
)

foreach ($service in $services) {
    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
}

# Configure Windows Firewall
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall firewall add rule name="Allow HTTP Out" dir=out action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="Allow HTTPS Out" dir=out action=allow protocol=TCP localport=443
```

### Registry Security Settings
```reg
Windows Registry Editor Version 5.00

; Disable autorun for all drives
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"NoDriveTypeAutoRun"=dword:000000ff

; Disable remote assistance
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance]
"fAllowToGetHelp"=dword:00000000

; Enable DEP for all programs
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management]
"ExecuteOptions"=dword:00000001

; Disable anonymous enumeration
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"RestrictAnonymous"=dword:00000001
"RestrictAnonymousSAM"=dword:00000001
```

## 🐧 Linux Security Hardening

### System Configuration
```bash
#!/bin/bash
# Linux hardening script

# Update system packages
apt update && apt upgrade -y

# Install security packages
apt install -y fail2ban ufw aide rkhunter chkrootkit

# Configure SSH security
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config

# Restart SSH service
systemctl restart sshd

# Configure firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw --force enable
```

### Kernel Security Parameters
```bash
# /etc/sysctl.d/99-security.conf
# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# Memory protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
```

### File System Security
```bash
# Set proper permissions on critical files
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 600 /boot/grub/grub.cfg
chmod 700 /root

# Configure file integrity monitoring
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Create daily AIDE check
cat > /etc/cron.daily/aide << 'EOF'
#!/bin/bash
aide --check | mail -s "AIDE Integrity Check" admin@company.com
EOF
chmod +x /etc/cron.daily/aide
```

## 🔥 Firewall Configurations

### pfSense Configuration
```xml
<!-- Basic pfSense firewall rules -->
<rule>
  <type>pass</type>
  <interface>wan</interface>
  <protocol>tcp</protocol>
  <destination>
    <port>22</port>
  </destination>
  <source>
    <address>trusted-ip-range</address>
  </source>
  <descr>SSH access from trusted networks</descr>
</rule>

<rule>
  <type>block</type>
  <interface>wan</interface>
  <protocol>any</protocol>
  <source>
    <any>1</any>
  </source>
  <destination>
    <any>1</any>
  </destination>
  <descr>Default deny all</descr>
</rule>
```

### iptables Rules
```bash
#!/bin/bash
# iptables hardening script

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from specific networks
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Rate limiting for SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

## 🌐 Web Server Hardening

### Apache Security Configuration
```apache
# /etc/apache2/conf-available/security.conf

# Hide server information
ServerTokens Prod
ServerSignature Off

# Security headers
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'"

# Disable dangerous methods
<LimitExcept GET POST HEAD>
    deny from all
</LimitExcept>

# Hide .htaccess files
<Files ".ht*">
    Require all denied
</Files>

# Disable server-status and server-info
<Location "/server-status">
    Require all denied
</Location>

<Location "/server-info">
    Require all denied
</Location>

# Timeout settings
Timeout 60
KeepAliveTimeout 15
```

### Nginx Security Configuration
```nginx
# /etc/nginx/nginx.conf security settings

# Hide server information
server_tokens off;

# Security headers
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Rate limiting
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

server {
    # SSL configuration
    listen 443 ssl http2;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    
    # Rate limiting
    location /login {
        limit_req zone=login burst=5 nodelay;
    }
    
    # Block common attack patterns
    location ~* \.(asp|aspx|cgi|jsp|php)$ {
        deny all;
    }
    
    # Disable access to sensitive files
    location ~ /\. {
        deny all;
    }
}
```

## 🗄️ Database Security Configurations

### MySQL/MariaDB Hardening
```sql
-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root login
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Create application user with limited privileges
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'appuser'@'localhost';

-- Configure secure settings in my.cnf
-- [mysqld]
-- bind-address = 127.0.0.1
-- skip-networking
-- log-error = /var/log/mysql/error.log
-- general-log = 1
-- general-log-file = /var/log/mysql/mysql.log

FLUSH PRIVILEGES;
```

### PostgreSQL Security
```sql
-- Create role with limited privileges
CREATE ROLE appuser WITH LOGIN PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE appdb TO appuser;
GRANT USAGE ON SCHEMA public TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO appuser;

-- postgresql.conf security settings
-- listen_addresses = 'localhost'
-- port = 5432
-- max_connections = 100
-- shared_preload_libraries = 'pg_stat_statements'
-- log_statement = 'all'
-- log_connections = on
-- log_disconnections = on
```

## ☁️ Cloud Security Configurations

### AWS Security Baseline
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "ec2:TerminateInstances",
        "rds:DeleteDBInstance",
        "s3:DeleteBucket"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

### Azure Security Configuration
```powershell
# Enable Azure Security Center
Register-AzResourceProvider -ProviderNamespace 'Microsoft.Security'

# Configure security policies
$resourceGroup = "production-rg"
$policy = @{
    "properties" = @{
        "displayName" = "Require HTTPS for storage accounts"
        "policyType" = "Custom"
        "mode" = "All"
        "policyRule" = @{
            "if" = @{
                "allOf" = @(
                    @{
                        "field" = "type"
                        "equals" = "Microsoft.Storage/storageAccounts"
                    }
                )
            }
            "then" = @{
                "effect" = "deny"
            }
        }
    }
}
```

## 🔧 Security Tool Configurations

### OSSEC Configuration
```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>admin@company.com</email_to>
    <smtp_server>localhost</smtp_server>
    <email_from>ossec@company.com</email_from>
  </global>

  <rules>
    <include>rules_config.xml</include>
    <include>pam_rules.xml</include>
    <include>sshd_rules.xml</include>
    <include>telnetd_rules.xml</include>
    <include>syslog_rules.xml</include>
    <include>arpwatch_rules.xml</include>
    <include>symantec-av_rules.xml</include>
    <include>symantec-ws_rules.xml</include>
    <include>pix_rules.xml</include>
    <include>named_rules.xml</include>
    <include>smbd_rules.xml</include>
    <include>vsftpd_rules.xml</include>
    <include>pure-ftpd_rules.xml</include>
    <include>proftpd_rules.xml</include>
    <include>ms_ftpd_rules.xml</include>
    <include>ftpd_rules.xml</include>
    <include>hordeimp_rules.xml</include>
    <include>roundcube_rules.xml</include>
    <include>wordpress_rules.xml</include>
    <include>cimserver_rules.xml</include>
    <include>vpopmail_rules.xml</include>
    <include>vmpop3d_rules.xml</include>
    <include>courier_rules.xml</include>
    <include>web_rules.xml</include>
    <include>web_appsec_rules.xml</include>
    <include>apache_rules.xml</include>
    <include>nginx_rules.xml</include>
    <include>php_rules.xml</include>
    <include>mysql_rules.xml</include>
    <include>postgresql_rules.xml</include>
    <include>ids_rules.xml</include>
    <include>squid_rules.xml</include>
    <include>firewall_rules.xml</include>
    <include>cisco-ios_rules.xml</include>
    <include>netscreenfw_rules.xml</include>
    <include>sonicwall_rules.xml</include>
    <include>postfix_rules.xml</include>
    <include>sendmail_rules.xml</include>
    <include>imapd_rules.xml</include>
    <include>mailscanner_rules.xml</include>
    <include>dovecot_rules.xml</include>
    <include>ms-exchange_rules.xml</include>
    <include>racoon_rules.xml</include>
    <include>vpn_concentrator_rules.xml</include>
    <include>spamd_rules.xml</include>
    <include>msauth_rules.xml</include>
    <include>mcafee_av_rules.xml</include>
    <include>trend-osce_rules.xml</include>
    <include>ms-se_rules.xml</include>
    <include>zeus_rules.xml</include>
    <include>solaris_bsm_rules.xml</include>
    <include>vmware_rules.xml</include>
    <include>ms_dhcp_rules.xml</include>
    <include>asterisk_rules.xml</include>
    <include>ossec_rules.xml</include>
    <include>attack_rules.xml</include>
    <include>local_rules.xml</include>
  </rules>

  <syscheck>
    <frequency>7200</frequency>
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
  </syscheck>

  <rootcheck>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_debian_linux_rcl.txt</system_audit>
  </rootcheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>
</ossec_config>
```

## 📋 Configuration Management

### Ansible Security Playbook
```yaml
---
- name: Linux Security Hardening
  hosts: linux_servers
  become: yes
  tasks:
    - name: Update all packages
      apt:
        update_cache: yes
        upgrade: dist
    
    - name: Install security packages
      apt:
        name:
          - fail2ban
          - ufw
          - aide
          - rkhunter
        state: present
    
    - name: Configure SSH security
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      with_items:
        - { regexp: '^PermitRootLogin', line: 'PermitRootLogin no' }
        - { regexp: '^PasswordAuthentication', line: 'PasswordAuthentication no' }
        - { regexp: '^MaxAuthTries', line: 'MaxAuthTries 3' }
      notify: restart sshd
    
    - name: Configure firewall
      ufw:
        rule: "{{ item.rule }}"
        port: "{{ item.port }}"
        proto: "{{ item.proto | default('tcp') }}"
      with_items:
        - { rule: 'allow', port: '22' }
        - { rule: 'allow', port: '80' }
        - { rule: 'allow', port: '443' }
    
    - name: Enable firewall
      ufw:
        state: enabled
        policy: deny
        direction: incoming

  handlers:
    - name: restart sshd
      service:
        name: sshd
        state: restarted
```

## 🎯 Compliance Templates

### PCI DSS Configuration Template
```bash
# PCI DSS Requirement 2.2 - System hardening standards
# Remove unnecessary services and applications
systemctl disable telnet
systemctl disable ftp
systemctl disable rsh

# PCI DSS Requirement 8.2 - Strong authentication
# Configure password complexity
authconfig --passminlen=8 --passminclass=4 --passmaxrepeat=3 --update

# PCI DSS Requirement 10.2 - Audit logs
# Configure comprehensive logging
auditctl -w /etc/passwd -p wa -k user_modification
auditctl -w /etc/group -p wa -k group_modification
auditctl -w /etc/shadow -p wa -k password_modification
```

### NIST 800-53 Controls
```yaml
# Access Control (AC)
access_control:
  ac_2_account_management:
    - automated_account_management: true
    - account_monitoring: enabled
    - inactive_account_disable: 90_days
  
  ac_3_access_enforcement:
    - mandatory_access_control: enabled
    - discretionary_access_control: enabled
    - role_based_access_control: enabled

# Audit and Accountability (AU)
audit_accountability:
  au_2_audit_events:
    - successful_logons: true
    - unsuccessful_logons: true
    - privileged_activities: true
  
  au_3_audit_record_content:
    - timestamp: required
    - user_identity: required
    - event_type: required
    - outcome: required
```

---

*These configurations provide security baselines and should be customized for specific environments and requirements. Always test configurations in non-production environments first.*