---
tags: [recon, no-creds, nmap, rustscan, scanning]
---

# Recon & Scanning

---

## Route by Finding

> After scanning, use this to decide where to go next. Multiple routes can apply simultaneously.
> **First:** look at the open ports as a picture — what kind of system is this? Web server, AD DC, database host, developer box? What is it likely doing, and what assumption would an admin have made that you can break? Write it down before opening any tool.


| What you found | Where to go |
|---|---|
| Port 80 / 443 | → [02_web_enum.md](./02_web_enum.md) |
| Port 139 / 445 (SMB) | → [03_service_enum.md](./03_service_enum.md) |
| Port 88 (Kerberos) | DC found → [06_active_directory.md](./06_active_directory.md) |
| Port 389 / 636 / 3268 (LDAP) | → [06_active_directory.md](./06_active_directory.md) |
| Port 5985 / 5986 (WinRM) | → [03_service_enum.md](./03_service_enum.md) — try found creds |
| Port 21 / 22 / 25 / 110 / 161 / 2049 / 3306 / 5432 | → [03_service_enum.md](./03_service_enum.md) |
| Multiple hosts + DC identified | → [06_active_directory.md](./06_active_directory.md) |
| Second NIC / internal route on compromised host | → [07_pivoting.md](./07_pivoting.md) |
| Credentials found anywhere | → [00_master_checklist.md Phase 4](./00_master_checklist.md) — spray immediately |
| Shell obtained | → [04_linux_privesc.md](./04_linux_privesc.md) or [05_windows_privesc.md](./05_windows_privesc.md) |

---

## Recommended Workflow

```bash
# Step 1 — RustScan: fast port discovery (all 65535 ports in seconds)
rustscan -a $TARGET --ulimit 5000 -b 500 -- -Pn 2>/dev/null | tee recon/rustscan.out

# Extract discovered ports into a variable
PORTS=$(grep -oP '\d+(?=/tcp)' recon/rustscan.out | tr '\n' ',' | sed 's/,$//')
echo "Ports: $PORTS"

# Step 2 — Nmap: deep scan on discovered ports only
sudo nmap -Pn -sC -sV -p $PORTS -oN recon/tcp.out $TARGET

# Step 3 — UDP: always run in background
sudo nmap -Pn -sU --top-ports 20 -oN recon/udp.out $TARGET &
```

---

## RustScan

```bash
# Single target (recommended first step)
rustscan -a $TARGET --ulimit 5000 -b 500 -- -Pn

# With nmap handoff in one command
rustscan -a $TARGET --ulimit 5000 -- -Pn -sC -sV -oN recon/tcp.out

# Subnet sweep
rustscan -a 192.168.1.0/24 --ulimit 5000
```

---

## Nmap (deep scan / fallback)

> Use for the detailed stage after rustscan, or as full fallback when rustscan is unavailable.

```bash
# Deep scan on specific ports (feed in rustscan results)
sudo nmap -Pn -sC -sV -p $PORTS -oN recon/tcp.out $TARGET

# Full TCP fallback (if rustscan unavailable)
sudo nmap -Pn -sC -sV -p- --open -oN recon/tcp.out $TARGET

# UDP top 20
sudo nmap -Pn -sU --top-ports 20 -oN recon/udp.out $TARGET

# UDP top 200 (when you suspect UDP services)
sudo nmap -Pn -sU -sV --top-ports 200 -oN recon/udp_200.out $TARGET

# Vulnerability scripts (noisy — run separately after foothold phase)
sudo nmap -Pn -sV --script vuln -p $PORTS $TARGET
```

### Useful flags

| Flag              | Purpose                                          |
| ----------------- | ------------------------------------------------ |
| `-Pn`             | Skip host discovery (assume up)                  |
| `-p-`             | All 65535 ports                                  |
| `--open`          | Only show open ports                             |
| `-sC`             | Default scripts                                  |
| `-sV`             | Version detection                                |
| `-oN`             | Normal output to file                            |
| `-oA`             | All formats (normal, xml, grepable)              |
| `--min-rate 5000` | Speed up scan (can miss ports on unstable links) |
| `-T4`             | Aggressive timing                                |

---

## AutoRecon (full automation)

```bash
sudo autorecon -o recon/ $TARGET

# Multiple targets
sudo autorecon -o recon/ $TARGET1 $TARGET2

# Specific ports only
sudo autorecon --only-scans-dir -o recon/ $TARGET
```

Output lands in `recon/results/$TARGET/`.

---

## Host Discovery (network ranges)

```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# ARP (local network only)
arp-scan --localnet
netdiscover -r 192.168.1.0/24

# fping
fping -ag 192.168.1.0/24 2>/dev/null

# When ICMP blocked (TCP ping)
nmap -sn -PS 80,443,22,21 192.168.1.0/24
```

---

## Banner Grabbing

```bash
# Netcat
nc -nnv $TARGET <port>

# Curl headers
curl -I http://$TARGET

# Telnet (SMTP, POP3)
telnet $TARGET 25
```

---

## DNS

```bash
# Zone transfer (try both TCP/UDP)
dig axfr @$TARGET $DOMAIN
dig axfr @$DNS_SERVER $DOMAIN

# Reverse lookup
nslookup $TARGET $TARGET

# Subdomain brute force
gobuster dns -d $DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.$DOMAIN" -u http://$TARGET --hw 0

# dnsrecon
dnsrecon -d $DOMAIN -t axfr
dnsrecon -d $DOMAIN -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt
```

---

## SNMP

```bash
# Community string brute
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $TARGET

# Walk with known community string
snmpwalk -c public -v1 -t 10 $TARGET
snmpwalk -c public -v2c $TARGET

# Formatted output
snmp-check $TARGET -c public

# Specific OIDs (Windows)
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.25   # Users
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.4.2.1.2  # Processes
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.6.13.1.3    # Open TCP ports
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.6.3.1.2  # Installed software
```

---

## NFS

```bash
# List exports
showmount -e $TARGET

# Mount (try v2 if v3 fails)
sudo mount -o rw,vers=2 $TARGET:/share /mnt
sudo mount -t nfs $TARGET:/share /mnt

# Check for no_root_squash (can write as root)
cat /etc/exports
```
