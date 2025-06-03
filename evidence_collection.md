# Evidence Collection and Documentation

Comprehensive methodology for collecting, organizing, and documenting evidence during penetration testing and vulnerability assessment activities.

## Evidence Collection Objectives

1. **Proof of Exploitation** - Demonstrate successful compromise
2. **Impact Assessment** - Show potential damage and access level
3. **Technical Documentation** - Provide detailed reproduction steps
4. **Business Justification** - Support remediation recommendations

## Pre-Exploitation Evidence

### Target Information Gathering

```bash
# System information collection
nmap -sV -O 192.168.1.10 > target_system_info.txt

# Network topology documentation
ip route show > network_topology.txt
arp -a > arp_table_before.txt

# Service enumeration results
nmap --script vuln 192.168.1.10 > vulnerability_scan.txt
```

### Screenshot Documentation

- Network scan results showing vulnerable services
- Vulnerability scanner output (Nmap, Nessus)
- Target system identification
- Initial access attempts

## During Exploitation Evidence

### Metasploit Session Documentation

```bash
# In msfconsole, log all activities
spool /tmp/metasploit_session.log

# Document exploit configuration
show options > exploit_config.txt

# Capture exploitation process
# Screenshot of successful exploit execution
# Session establishment confirmation
```

### Network Traffic Capture

```bash
# Start packet capture before exploitation
tcpdump -i eth0 -w exploitation_traffic.pcap host 192.168.1.10

# Alternative with Wireshark
# Start capture, apply filter: ip.addr == 192.168.1.10
# Save capture file with descriptive name
```

## Post-Exploitation Evidence

### System Access Verification

```bash
# From Meterpreter session
getuid > current_privileges.txt
sysinfo > system_information.txt

# Take screenshot for visual proof
screenshot

# Process listing
ps > running_processes.txt
```

### Privilege Level Documentation

```bash
# Windows privilege enumeration
whoami /all > user_privileges.txt
net user > user_accounts.txt
net localgroup administrators > admin_group.txt

# Linux privilege enumeration
id > user_identity.txt
sudo -l > sudo_privileges.txt
cat /etc/passwd > system_users.txt
```

### File System Access Evidence

```bash
# Demonstrate file system access
ls C:\ > c_drive_listing.txt
dir C:\Users > users_directory.txt

# Access sensitive directories
ls /etc > etc_directory.txt
cat /etc/shadow > shadow_file.txt  # If accessible
```

### Network Configuration Evidence

```bash
# Network interface information
ipconfig /all > network_config.txt  # Windows
ifconfig -a > network_interfaces.txt  # Linux

# Routing table
route print > routing_table.txt  # Windows
ip route show > routing_info.txt  # Linux

# Active connections
netstat -an > network_connections.txt
```

## Data Exfiltration Proof of Concept

### Sensitive File Identification

```bash
# Search for sensitive files
search -f *.txt -d C:\Users > text_files.txt
search -f *.docx -d C:\Users > document_files.txt
search -f *.pdf -d C:\ > pdf_files.txt

# Database files
search -f *.mdb -d C:\ > access_databases.txt
search -f *.db -d C:\ > database_files.txt
```

### Sample Data Extraction

```bash
# Download sample files (non-sensitive)
download C:\Users\Public\sample.txt
download C:\Windows\System32\drivers\etc\hosts

# Create proof-of-access file
echo "Penetration test evidence - $(date)" > evidence_file.txt
upload evidence_file.txt C:\temp\
```

## Persistence Evidence

### Registry Modifications

```bash
# Document registry changes for persistence
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" > startup_programs.txt

# If persistence was established
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /d "C:\temp\backdoor.exe"
```

### Service Installation

```bash
# Document installed services
sc query > installed_services.txt

# If service persistence was used
sc create "Windows Security Update" binpath= "C:\temp\service.exe" start= auto
```

## Evidence Organization Structure

```
evidence_collection_YYYYMMDD/
├── 01_reconnaissance/
│   ├── network_scan_results.txt
│   ├── vulnerability_assessment.txt
│   └── target_identification_screenshots/
├── 02_exploitation/
│   ├── metasploit_session_log.txt
│   ├── exploit_screenshots/
│   └── network_traffic_capture.pcap
├── 03_post_exploitation/
│   ├── system_information/
│   ├── privilege_evidence/
│   ├── file_access_proof/
│   └── network_configuration/
├── 04_persistence/
│   ├── registry_modifications.txt
│   ├── service_installation.txt
│   └── backdoor_placement/
└── 05_cleanup/
    ├── changes_reverted.txt
    └── system_restoration_proof/
```

## Critical Screenshots to Capture

### Before Exploitation
- Target system identification (OS, services)
- Vulnerability scan results
- Network topology

### During Exploitation
- Metasploit exploit execution
- Session establishment
- Initial access confirmation

### After Exploitation
- Privilege level (getuid/whoami output)
- System information display
- File system access demonstration
- Network configuration access

## Evidence Chain of Custody

### Documentation Requirements

```markdown
## Evidence Item: [Description]
- **Date/Time**: 2025-01-15 14:30:00 UTC
- **Collector**: Giammarco Galassi
- **Target System**: 192.168.1.10 (Windows 7 SP1)
- **Collection Method**: Meterpreter session
- **File Hash**: SHA256: [hash]
- **Storage Location**: /evidence/2025-01-15/
- **Chain of Custody**: Maintained in lab environment
```

### File Integrity Verification

```bash
# Generate checksums for evidence files
sha256sum evidence_file.txt > file_checksums.txt
md5sum *.txt > md5_checksums.txt

# Verify integrity later
sha256sum -c file_checksums.txt
```

## Report Integration

### Executive Summary Evidence
- High-level impact screenshots
- Business risk demonstration
- Compliance violation proof

### Technical Details Evidence
- Step-by-step exploitation process
- Configuration screenshots
- Command output logs
- Network traffic analysis

### Remediation Verification
- Before/after comparison screenshots
- Patch verification evidence
- Security control implementation proof

## Legal and Ethical Considerations

### Data Handling
- **Minimize data collection** - Only what's necessary for proof
- **No personal information** extraction
- **Secure storage** of evidence files
- **Proper disposal** after assessment completion

### Documentation Standards
- **Timestamp all evidence** with accurate date/time
- **Document methodology** used for collection
- **Maintain chain of custody** records
- **Ensure reproducibility** of evidence collection

## Cleanup Documentation

### System Restoration Evidence

```bash
# Document cleanup activities
# Remove uploaded files
rm C:\temp\evidence_file.txt

# Revert registry changes
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate"

# Remove installed services
sc delete "Windows Security Update"

# Verify cleanup completion
ls C:\temp\ > cleanup_verification.txt
```

### Final System State

```bash
# Capture final system state
netstat -an > final_network_state.txt
ps > final_process_list.txt
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" > final_startup_programs.txt
```

## Evidence Retention Policy

- **Lab Environment**: Evidence retained for learning purposes
- **Professional Engagement**: Follow client retention requirements
- **Personal Study**: Maintain for skill development and portfolio
- **Disposal**: Secure deletion when no longer needed

