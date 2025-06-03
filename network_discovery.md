# Network Discovery and Service Enumeration

Comprehensive methodology for discovering hosts, services, and potential attack vectors in target networks.

## Discovery Phases Overview

1. **Network Mapping** - Identify live hosts and network topology
2. **Port Scanning** - Discover open services and protocols
3. **Service Enumeration** - Determine service versions and configurations
4. **Vulnerability Assessment** - Identify potential security weaknesses

## Phase 1: Network Mapping

### Host Discovery

```bash
# Ping sweep (ICMP-based discovery)
nmap -sn 192.168.1.0/24

# ARP scan (Layer 2 discovery - more reliable on local networks)
arp-scan -l
arp-scan 192.168.1.0/24

# Alternative with netdiscover
netdiscover -r 192.168.1.0/24
```

### Network Topology Identification

```bash
# Check local routing table
ip route show

# Identify default gateway
ip route | grep default

# Check network interfaces
ip addr show

# ARP table analysis
arp -a
```

## Phase 2: Port Scanning

### Basic Port Scanning

```bash
# Quick scan of top 1000 ports
nmap -T4 192.168.1.10

# Full TCP port scan
nmap -p- 192.168.1.10

# Specific port scanning
nmap -p 21,22,23,25,53,80,135,139,443,445 192.168.1.10

# UDP service discovery
nmap -sU --top-ports 100 192.168.1.10
```

### Stealth Scanning Options

```bash
# SYN scan (default, requires root)
nmap -sS 192.168.1.10

# Connect scan (no root required)
nmap -sT 192.168.1.10

# FIN scan (firewall evasion)
nmap -sF 192.168.1.10
```

## Phase 3: Service Enumeration

### Version Detection

```bash
# Service version detection
nmap -sV 192.168.1.10

# Operating system detection
nmap -O 192.168.1.10

# Aggressive scan (includes version, OS, script scanning)
nmap -A 192.168.1.10
```

### Protocol-Specific Enumeration

#### SMB/NetBIOS Services
```bash
# SMB service enumeration
nmap -p 445 --script smb-enum-shares 192.168.1.10
nmap -p 445 --script smb-enum-users 192.168.1.10
nmap -p 445 --script smb-os-discovery 192.168.1.10

# NetBIOS information
nmap -p 139 --script nbstat 192.168.1.10

# SMB vulnerability scanning
nmap --script smb-vuln-* 192.168.1.10
```

#### Web Services
```bash
# HTTP service enumeration
nmap -p 80,443 --script http-enum 192.168.1.10
nmap -p 80,443 --script http-headers 192.168.1.10
nmap -p 80,443 --script http-methods 192.168.1.10

# SSL/TLS enumeration
nmap -p 443 --script ssl-enum-ciphers 192.168.1.10
```

#### SSH Services
```bash
# SSH enumeration
nmap -p 22 --script ssh-hostkey 192.168.1.10
nmap -p 22 --script ssh-auth-methods 192.168.1.10
```

#### FTP Services
```bash
# FTP enumeration
nmap -p 21 --script ftp-anon 192.168.1.10
nmap -p 21 --script ftp-bounce 192.168.1.10
```

## Phase 4: Advanced Service Analysis

### Banner Grabbing

```bash
# Manual banner grabbing with netcat
nc -nv 192.168.1.10 80
nc -nv 192.168.1.10 22
nc -nv 192.168.1.10 25

# Automated banner grabbing
nmap -sV --version-intensity 9 192.168.1.10
```

### Script Scanning

```bash
# Default script scan
nmap -sC 192.168.1.10

# Vulnerability scanning scripts
nmap --script vuln 192.168.1.10

# Specific script categories
nmap --script discovery 192.168.1.10
nmap --script safe 192.168.1.10
```

## Common Services and Default Ports

### Critical Services to Check

| Port | Service | Enumeration Commands |
|------|---------|---------------------|
| 21 | FTP | `nmap --script ftp-* -p 21` |
| 22 | SSH | `nmap --script ssh-* -p 22` |
| 23 | Telnet | `nc -nv target 23` |
| 25 | SMTP | `nmap --script smtp-* -p 25` |
| 53 | DNS | `nmap --script dns-* -p 53` |
| 80 | HTTP | `nmap --script http-* -p 80` |
| 135 | RPC | `nmap --script rpc-* -p 135` |
| 139 | NetBIOS | `nmap --script netbios-* -p 139` |
| 443 | HTTPS | `nmap --script ssl-* -p 443` |
| 445 | SMB | `nmap --script smb-* -p 445` |

### Windows-Specific Services

```bash
# Windows RPC services
nmap -p 135 --script rpc-grind 192.168.1.10

# Windows Remote Desktop
nmap -p 3389 --script rdp-enum-encryption 192.168.1.10

# Windows DNS
nmap -p 53 --script dns-zone-transfer 192.168.1.10
```

## Documentation and Analysis

### Output Management

```bash
# Save results in multiple formats
nmap -sV -A 192.168.1.10 -oA complete_scan

# This creates:
# complete_scan.nmap (normal output)
# complete_scan.xml (XML format)
# complete_scan.gnmap (grepable format)
```

### Results Analysis

```bash
# Parse XML output with specific tools
# Extract open ports
grep "portid" complete_scan.xml | grep "open"

# Extract service versions
grep "service name" complete_scan.xml

# Analyze grepable output
grep "Up" complete_scan.gnmap
grep "Ports:" complete_scan.gnmap
```

## Target Prioritization

### High-Value Targets

1. **Domain Controllers** (ports 53, 88, 389, 636)
2. **File Servers** (ports 445, 139, 2049)
3. **Web Servers** (ports 80, 443, 8080, 8443)
4. **Database Servers** (ports 1433, 3306, 5432, 1521)
5. **Remote Access** (ports 22, 23, 3389, 5900)

### Vulnerability Indicators

- **Unpatched systems** with known CVEs
- **Default credentials** on services
- **Unnecessary services** running
- **Weak encryption** protocols (SSLv2, weak ciphers)
- **Anonymous access** enabled (FTP, SMB shares)

## Evasion Techniques

### Timing and Rate Control

```bash
# Slow scan to avoid detection
nmap -T1 192.168.1.10

# Custom timing
nmap --scan-delay 1s 192.168.1.10
nmap --max-rate 50 192.168.1.10
```

### Fragmentation and Decoys

```bash
# Packet fragmentation
nmap -f 192.168.1.10

# Decoy scanning
nmap -D RND:10 192.168.1.10
nmap -D 192.168.1.5,192.168.1.6,ME,192.168.1.8 192.168.1.10
```

## Next Steps After Discovery

1. **Vulnerability Assessment** - Use discovered services to identify specific vulnerabilities
2. **Credential Testing** - Test for default or weak passwords
3. **Service Exploitation** - Target identified vulnerable services
4. **Lateral Movement** - Use compromised systems to discover internal networks

## Documentation Template

```
Target: 192.168.1.10
OS: Windows 7 Professional SP1
Open Ports:
- 135/tcp: msrpc
- 139/tcp: netbios-ssn
- 445/tcp: microsoft-ds

Vulnerabilities Found:
- MS17-010 (SMB)
- SMBv1 enabled

Recommended Actions:
1. Apply MS17-010 patch
2. Disable SMBv1
3. Configure firewall rules
```