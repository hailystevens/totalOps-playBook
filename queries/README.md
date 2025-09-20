# Security Queries & Analytics 📊

Collection of queries for SIEM platforms, databases, log analysis, threat hunting, and security analytics across various systems and tools.

## 📋 Query Categories

### SIEM Queries
- [Splunk Queries](splunk/README.md)
- [Elastic Stack (ELK)](elastic/README.md)
- [IBM QRadar](qradar/README.md)
- [Microsoft Sentinel](sentinel/README.md)
- [ArcSight](arcsight/README.md)

### Database Queries
- [SQL Server Security](databases/sqlserver.md)
- [MySQL Security](databases/mysql.md)
- [PostgreSQL Security](databases/postgresql.md)
- [Oracle Security](databases/oracle.md)
- [MongoDB Security](databases/mongodb.md)

### Cloud Platform Queries
- [AWS CloudTrail](cloud/aws-cloudtrail.md)
- [Azure Activity Logs](cloud/azure-logs.md)
- [Google Cloud Audit](cloud/gcp-audit.md)
- [Office 365](cloud/o365-logs.md)

### Threat Hunting
- [Advanced Persistent Threats](threat-hunting/apt-hunting.md)
- [Malware Detection](threat-hunting/malware-detection.md)
- [Lateral Movement](threat-hunting/lateral-movement.md)
- [Data Exfiltration](threat-hunting/data-exfiltration.md)

## 🔍 Splunk Queries

### Authentication and Access
```spl
# Failed login attempts by source IP
index=security EventCode=4625 
| stats count by src_ip 
| where count > 10 
| sort -count

# Successful logins after multiple failures
index=security (EventCode=4625 OR EventCode=4624) 
| transaction src_ip startswith=eval(EventCode=4625) endswith=eval(EventCode=4624) 
| where eventcount > 5

# Privileged account usage
index=security EventCode=4672 
| lookup user_lookup.csv user OUTPUT department 
| stats count by user, department 
| sort -count

# Off-hours login attempts
index=security EventCode=4624 
| eval hour=strftime(_time, "%H") 
| where hour < 6 OR hour > 22 
| stats count by user, src_ip

# Multiple failed logins followed by success
index=security (EventCode=4625 OR EventCode=4624) user=* 
| streamstats current=f last(EventCode) as last_event by user 
| where EventCode=4624 AND last_event=4625 
| stats count by user, src_ip
```

### Network Security
```spl
# DNS tunneling detection
index=network sourcetype=dns 
| stats avg(query_length) as avg_length, count by src_ip 
| where avg_length > 50 AND count > 100

# Large data transfers
index=network 
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip 
| where total_bytes > 1000000000 
| sort -total_bytes

# Suspicious network connections
index=network dest_port IN (1337, 31337, 4444, 5555) 
| stats count by src_ip, dest_ip, dest_port 
| sort -count

# Beaconing detection
index=network 
| bucket _time span=1h 
| stats count by src_ip, dest_ip, _time 
| eventstats avg(count) as avg_conn by src_ip, dest_ip 
| where count > avg_conn * 1.5

# Port scanning detection
index=network 
| stats dc(dest_port) as unique_ports by src_ip, dest_ip 
| where unique_ports > 20 
| sort -unique_ports
```

### Malware and Suspicious Activity
```spl
# PowerShell execution with encoded commands
index=windows sourcetype=powershell 
| search "EncodedCommand" OR "-enc" OR "FromBase64String" 
| stats count by Computer, User

# Suspicious process creation
index=sysmon EventCode=1 
| search CommandLine="*powershell*" AND (CommandLine="*DownloadString*" OR CommandLine="*Invoke-Expression*") 
| table _time, Computer, User, CommandLine

# File execution from temp directories
index=sysmon EventCode=1 
| search Image="*\\temp\\*" OR Image="*\\tmp\\*" OR Image="*\\appdata\\local\\temp\\*" 
| stats count by Computer, Image

# Unsigned or suspicious binaries
index=sysmon EventCode=1 
| search NOT (Signed=true) 
| stats count by Image, Company 
| sort -count

# Registry modifications in startup locations
index=sysmon EventCode=13 
| search TargetObject="*\\Microsoft\\Windows\\CurrentVersion\\Run*" 
| table _time, Computer, TargetObject, Details
```

## 📊 Elastic Stack (ELK) Queries

### Kibana Query Language (KQL)
```kql
# Failed authentication attempts
event.code:4625 AND winlog.event_data.Status:0xC000006D

# Suspicious PowerShell activity
process.name:powershell.exe AND process.command_line:(*DownloadString* OR *Invoke-Expression*)

# Network connections to suspicious IPs
network.direction:outbound AND destination.ip:(192.168.1.100 OR 10.0.0.50)

# File modifications in system directories
event.category:file AND file.path:C\:\\Windows\\System32\\* AND event.action:modified

# User account creation
event.code:4720 AND event.outcome:success
```

### Elasticsearch DSL Queries
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"event.code": "4625"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ],
      "must_not": [
        {"term": {"source.ip": "192.168.1.100"}}
      ]
    }
  },
  "aggs": {
    "failed_logins_by_ip": {
      "terms": {
        "field": "source.ip",
        "size": 10
      }
    }
  }
}
```

## 🛡️ Microsoft Sentinel (KQL)

### Advanced Threat Detection
```kql
// Suspicious login patterns
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 5
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == 0
    | project UserPrincipalName, IPAddress, SuccessTime = TimeGenerated
) on UserPrincipalName, IPAddress
| where SuccessTime > TimeGenerated

// Impossible travel detection
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| project UserPrincipalName, TimeGenerated, Location, IPAddress
| sort by UserPrincipalName, TimeGenerated
| serialize
| extend PreviousLocation = prev(Location), PreviousTime = prev(TimeGenerated)
| where UserPrincipalName == prev(UserPrincipalName)
| where Location != PreviousLocation
| extend TimeDiff = datetime_diff('hour', TimeGenerated, PreviousTime)
| where TimeDiff < 2 and TimeDiff > 0

// Mass file download detection
OfficeActivity
| where TimeGenerated > ago(1d)
| where Operation == "FileDownloaded"
| summarize DownloadCount = count() by UserId, bin(TimeGenerated, 1h)
| where DownloadCount > 50
```

## 🏗️ Database Security Queries

### SQL Server Security Monitoring
```sql
-- Failed login attempts
SELECT 
    login_time,
    login_name,
    client_net_address,
    error_number,
    error_message
FROM sys.dm_exec_sessions s
INNER JOIN sys.dm_exec_connections c ON s.session_id = c.session_id
WHERE login_name NOT IN ('sa', 'system')
    AND error_number IS NOT NULL;

-- Privilege escalation attempts
SELECT 
    session_id,
    login_time,
    login_name,
    program_name,
    host_name,
    last_request_start_time
FROM sys.dm_exec_sessions
WHERE is_user_process = 1
    AND original_login_name != login_name;

-- Suspicious query patterns
SELECT TOP 10
    creation_time,
    last_execution_time,
    execution_count,
    total_worker_time,
    text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle)
WHERE text LIKE '%xp_cmdshell%'
    OR text LIKE '%sp_configure%'
    OR text LIKE '%openrowset%'
ORDER BY last_execution_time DESC;
```

### MySQL Security Queries
```sql
-- Monitor privileged operations
SELECT 
    event_time,
    user_host,
    command_type,
    argument
FROM mysql.general_log
WHERE command_type IN ('Connect', 'Query', 'Execute')
    AND (argument LIKE '%DROP%' 
         OR argument LIKE '%CREATE USER%'
         OR argument LIKE '%GRANT%')
ORDER BY event_time DESC;

-- Failed connection attempts
SELECT 
    DATE(event_time) as date,
    HOUR(event_time) as hour,
    user_host,
    COUNT(*) as failed_attempts
FROM mysql.general_log
WHERE command_type = 'Connect'
    AND argument LIKE '%Access denied%'
GROUP BY DATE(event_time), HOUR(event_time), user_host
HAVING failed_attempts > 10;
```

## ☁️ Cloud Security Queries

### AWS CloudTrail Analysis
```json
{
  "eventTime": {"$gte": "2025-01-01T00:00:00Z"},
  "errorCode": {"$exists": true},
  "sourceIPAddress": {"$not": {"$regex": "^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[01])\\."}}
}
```

### Azure Activity Log Queries
```kql
AzureActivity
| where TimeGenerated > ago(24h)
| where ActivityStatus == "Failed"
| where OperationName contains "write" or OperationName contains "delete"
| summarize count() by Caller, OperationName, ResourceGroup
| order by count_ desc

AzureActivity
| where TimeGenerated > ago(7d)
| where Caller !endswith "@company.com"
| where OperationName in ("Microsoft.Authorization/roleAssignments/write", 
                         "Microsoft.Authorization/roleDefinitions/write")
| project TimeGenerated, Caller, OperationName, Resource, ResourceGroup
```

## 🎯 Threat Hunting Queries

### Advanced Persistent Threat (APT) Detection
```spl
# Living off the land techniques
index=sysmon EventCode=1 
| search (Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe") 
| search (CommandLine="*javascript*" OR CommandLine="*vbscript*" OR CommandLine="*http*") 
| stats count by Computer, Image, CommandLine

# Suspicious scheduled tasks
index=windows sourcetype="wineventlog:security" EventCode=4698 
| search TaskName="*update*" OR TaskName="*system*" OR TaskName="*adobe*" 
| table _time, Computer, TaskName, TaskContent

# DLL side-loading detection
index=sysmon EventCode=7 
| search NOT (Signed=true AND SignatureStatus="Valid") 
| stats count by Computer, ImageLoaded, Image 
| where count > 1
```

### Lateral Movement Detection
```spl
# Pass-the-hash detection
index=security EventCode=4624 LogonType=3 
| search NOT (Account_Name="*$" OR Account_Name="ANONYMOUS LOGON") 
| eval src_dest=src_ip."|".dest_ip 
| stats dc(dest_ip) as unique_destinations by Account_Name, src_ip 
| where unique_destinations > 5

# Remote execution via WMI
index=sysmon EventCode=1 Image="*\\wmiprvse.exe" 
| search ParentImage="*\\wmiprvse.exe" 
| stats count by Computer, CommandLine

# SMB lateral movement
index=network dest_port=445 
| stats dc(dest_ip) as unique_targets by src_ip 
| where unique_targets > 10 
| sort -unique_targets
```

## 📈 Performance and Optimization

### Query Optimization Tips
```spl
# Use time-based filtering early
index=security earliest=-24h@h latest=now 
| search EventCode=4625

# Leverage summary indexing for frequent searches
| collect index=summary_security source="failed_logins"

# Use statistical commands efficiently
| stats count by field1, field2 
| sort -count 
| head 10
```

### Index Management
```spl
# Monitor index sizes and performance
| rest /services/data/indexes 
| eval size_gb=round(currentDBSizeMB/1024,2) 
| table title, size_gb, maxDataSize 
| sort -size_gb
```

## 🎓 Query Development Best Practices

### Security Considerations
- Use least privilege access for query execution
- Sanitize user inputs in parameterized queries
- Implement query result filtering
- Monitor query performance and resource usage
- Regular review and update of detection rules

### Documentation Standards
- Comment complex queries thoroughly
- Include use cases and expected results
- Document data sources and field mappings
- Maintain version control for query libraries
- Provide troubleshooting guides for common issues