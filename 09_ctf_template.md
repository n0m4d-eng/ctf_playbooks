---
tags: [ctf, template, workflow, report]
machine:
ip:
os:
platform: # HTB / THM / OSCP / CPTS
difficulty: # Easy / Medium / Hard / Insane
date_started:
date_completed:
status: in-progress # in-progress / rooted / abandoned
---

# CTF Machine Template

> Copy this file to `~/notes/machines/<platform>-<name>.md` for each machine.

---

## Hypothesis

> Before running any tool: what kind of system is this and what is it doing?
> What would have to be misconfigured or wrong for it to be exploitable?

---

## Recon

### Open Ports

```
paste rustscan / nmap output here
```

### Key Findings

- Port — service — version — notable detail
- Port — service — version — notable detail

---

## Attack Path

### Foothold

## **What I tried that didn't work:**

**What worked:**

```bash
# commands here
```

### Privilege Escalation

## **What I tried that didn't work:**

**What worked:**

```bash
# commands here
```

---

## Loot

| Item             | Value |
| ---------------- | ----- |
| local.txt        |       |
| proof.txt        |       |
| Credentials      |       |
| Hashes           |       |
| SSH keys / certs |       |

---

## Screenshots

- [ ] `whoami && hostname && cat proof.txt` — required for OSCP
- [ ] Key steps (upload, shell, privesc trigger)

---

## Key Insight

> What was the actual crack? What assumption did the box make that you broke?

## What I'd Do Differently

> What signal did you see but ignore or dismiss too quickly?
> What would you look for first if you hit this machine again?
