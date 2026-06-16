# OSCP Playbooks

Field reference for active engagements. Navigate with `/` search in nvim or `:find`.

| File | Use When |
|------|----------|
| [00_master_checklist.md](./00_master_checklist.md) | Start of every box — full phase-by-phase flow |
| [01_recon.md](./01_recon.md) | Scanning, nmap, DNS, SNMP, NFS |
| [02_web_enum.md](./02_web_enum.md) | Any HTTP/HTTPS port found |
| [03_service_enum.md](./03_service_enum.md) | Per-port enumeration (FTP, SMB, MySQL, etc.) |
| [04_linux_privesc.md](./04_linux_privesc.md) | Got Linux shell, need root |
| [05_windows_privesc.md](./05_windows_privesc.md) | Got Windows shell, need SYSTEM/admin |
| [06_active_directory.md](./06_active_directory.md) | Domain environment |
| [07_pivoting.md](./07_pivoting.md) | Found internal network, need to pivot |

## nvim tips

```vim
" Open a file by name
:find 04_linux*

" Search all playbooks for a term
:vimgrep /SeImpersonate/ playbooks/*.md
:copen

" Jump to next heading
/^##

" Open file under cursor (standard markdown links don't work natively, but:)
gf   " works if cursor is on a plain filename
```
