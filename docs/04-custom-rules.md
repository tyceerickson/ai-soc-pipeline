# 04 — Custom Wazuh Rules & Decoders

## Overview

Wazuh ships with built-in rules for many log sources but has no native support for honeypot events. This project adds custom decoders to parse the honeypot JSON formats and custom rules to assign severity and MITRE ATT&CK mappings. Two rule files are used:

- `config/wazuh-cowrie-rules.xml` — Cowrie SSH/Telnet (IDs **100100–100191**, 29 rules)
- `config/wazuh-honeypot-web-rules.xml` — Dionaea + nginx (IDs **100200–100344**, 28 rules)

> **Rebuilt June 2026 for per-behavior MITRE accuracy.** The ruleset was re-engineered so each rule tags the *single correct* MITRE technique/tactic for the behavior it detects — 57 rules covering 27 distinct techniques across ~12 tactics, grounded in the lab's real captured attacker behavior. The snippets below are illustrative of structure and intent; the authoritative current definitions live in the two XML files in `config/`.

---

## Decoding

The honeypot feeds emit one JSON object per line, each wrapped under a top-level `data` key — e.g. `{"data": {"eventid": "cowrie.login.success", "honeypot": "cowrie", "src_ip": "...", ...}}`. Wazuh's built-in JSON decoder (`<decoded_as>json</decoded_as>`) then exposes every field in the `data.*` namespace (`data.eventid`, `data.honeypot`, `data.src_ip`, `data.username`, `data.password`, `data.input`, `data.sha256`, `data.http_path`, etc.), which the rules match on.

> **Why the `data` wrapper matters.** The parsers/forwarders (`forward_cowrie.py`, `parse_nginx.py`, `parse_dionaea.py`) deliberately wrap each event as `{"data": {...}}` so Wazuh decodes fields as `data.*`. An earlier revision emitted flat events (top-level `eventid`/`honeypot`), which the `<field name="data.honeypot">` rules never matched — producing zero alerts. All three honeypots now use the identical wrapped structure. An OpenSearch ingest-pipeline processor additionally flattens a legacy double-nested `data.data.*` → `data.*` edge case (see `03-log-ingestion-setup.md`).

---

## Rule Severity Scale (Wazuh)

| Level | Severity | Description |
|-------|----------|-------------|
| 0–6   | Low      | Informational — session lifecycle, connection events |
| 7–11  | Medium   | Notable — brute-force attempts, scanning, known-bad credentials |
| 12–14 | High     | Serious — successful login, command execution, **malware capture** |
| 15    | Critical | Urgent — SSH key implant, persistence established |

---

## Cowrie Rules (illustrative — see `config/wazuh-cowrie-rules.xml`, IDs 100100–100191)

The cowrie ruleset chains behavior rules off a base event rule. Session-lifecycle noise (`connect`/`closed`/`kex`) is matched at **level 0** so it is searchable but never floods the alert stream. Each behavior rule carries the single correct technique.

```xml
<group name="cowrie,honeypot,ssh,">

  <!-- Base anchor (level 0 — no alert) -->
  <rule id="100100" level="0">
    <decoded_as>json</decoded_as>
    <field name="data.honeypot">cowrie</field>
    <description>Cowrie honeypot event (base)</description>
  </rule>

  <!-- Session lifecycle noise — suppressed at level 0 -->
  <rule id="100101" level="0">
    <if_sid>100100</if_sid>
    <field name="data.eventid" type="pcre2">^cowrie\.(session\.(connect|closed|params)|log\.closed|client\.)</field>
    <description>Cowrie: session/client lifecycle event (noise)</description>
  </rule>

  <!-- Failed login -->
  <rule id="100110" level="4">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.login.failed</field>
    <description>Cowrie: SSH/Telnet failed login [$(data.username)/$(data.password)]</description>
    <mitre><id>T1110</id></mitre>
  </rule>

  <!-- Brute force (10+ failures / 120s) -->
  <rule id="100111" level="9" frequency="10" timeframe="120">
    <if_matched_sid>100110</if_matched_sid>
    <same_field>data.src_ip</same_field>
    <description>Cowrie: SSH brute force — 10+ failed logins/120s from $(data.src_ip)</description>
    <mitre><id>T1110</id></mitre>
  </rule>

  <!-- Successful login — Credential Access (the guessing) + Initial Access (valid creds) -->
  <rule id="100112" level="10">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.login.success</field>
    <description>Cowrie: Successful SSH login [$(data.username)/$(data.password)] from $(data.src_ip) — honeypot compromised</description>
    <mitre><id>T1110</id><id>T1078</id></mitre>
  </rule>

  <!-- Base command (generic Execution; child rules below override with specific tactics) -->
  <rule id="100120" level="5">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.command.input</field>
    <description>Cowrie: Command executed: $(data.input)</description>
    <mitre><id>T1059</id></mitre>
  </rule>

  <!-- Discovery: uname / cpuinfo / lscpu -->
  <rule id="100130" level="6">
    <if_sid>100120</if_sid>
    <field name="data.input" type="pcre2">(?i)\buname\b|/proc/cpuinfo|\blscpu\b|\bnproc\b</field>
    <description>Cowrie: System information discovery — $(data.input)</description>
    <mitre><id>T1082</id></mitre>
  </rule>

  <!-- Persistence: SSH authorized_keys backdoor (mdrfckr family) -->
  <rule id="100150" level="13">
    <if_sid>100120</if_sid>
    <field name="data.input" type="pcre2">(?i)ssh-rsa\s+AAAA|authorized_keys</field>
    <description>Cowrie: SSH authorized_keys backdoor implant — $(data.input)</description>
    <mitre><id>T1098.004</id></mitre>
  </rule>

  <!-- Defense Evasion: chattr / lockr anti-removal -->
  <rule id="100160" level="10">
    <if_sid>100120</if_sid>
    <field name="data.input" type="pcre2">(?i)\bchattr\s+[-+][ia]|\blockr\b</field>
    <description>Cowrie: File attribute tampering (anti-removal) — $(data.input)</description>
    <mitre><id>T1222.002</id></mitre>
  </rule>

</group>
```

The full file maps the lab's real captured behaviors to distinct techniques: Discovery variants (T1082/T1033/T1057/T1016/T1518), Ingress Tool Transfer (T1105 — wget/curl), payload execution (T1059/T1204), scheduled-task & account persistence (T1053.003/T1136.001/T1098), indicator removal & impair-defenses (T1070/T1562.001), guardrail evasion (T1480), credential/data access (T1552.001), cryptomining intent (T1496), tunneling (T1090), and telnet exploit (T1190).

---

## Dionaea + nginx Rules (see `config/wazuh-honeypot-web-rules.xml`, IDs 100200–100344, 28 rules)

Highlights:

| Rule(s) | Level | Event | MITRE |
|------|-------|-------|-------|
| Dionaea SMB service probe | 5 | `dionaea.connection.smbd` | T1021.002 (Remote Services: SMB) |
| Dionaea MySQL/MSSQL probe | 5 | `dionaea.connection.{mysqld,mssqld}` | T1190 |
| Dionaea generic service probe | 4 | `dionaea.connection.*` | T1046 |
| Dionaea DB login / brute force | 7–10 | `dionaea.login.*` | T1110 |
| **Dionaea malware binary captured** | **14** | `dionaea.binary.captured` | **T1105** |
| Dionaea active malware distributor (3+/600s) | 15 | freq on captured | T1105 |
| nginx web probe (404) / scanner request | 3 | `nginx.probe.404`, `nginx.request.*` | T1595.003 |
| nginx `.env` credential-theft probe | 9 | `nginx.probe.env_file` | T1552.001 |
| nginx `.git` exposure probe | 8 | `nginx.probe.git` | T1213 |
| nginx CVE probes (WordPress/Tomcat/router/Hikvision) | 6–9 | `nginx.probe.*` | T1190 |
| nginx Log4Shell probe | 13 | `nginx.probe.log4shell` | T1190 / T1059 |
| nginx automated/multi-CVE scanner (freq) | 9–11 | correlation | T1595.003 |
| nginx scanner-identity (spoofed-browser / no-UA / HTTP-library) | 4–9 | `data.scanner_type` | T1595.003 / T1036 |

The `dionaea.binary.captured` rule carries the SHA256, source IP, service, and (when enriched) the VirusTotal verdict, surfacing each real malware capture as a Critical-severity alert.

---

## MITRE ATT&CK Mapping Summary

The rebuilt ruleset covers **27 distinct techniques across ~12 tactics**. Each rule maps to the single correct technique for the behavior it detects (no over-tagging).

| Tactic | Techniques | Source |
|--------|-----------|--------|
| Reconnaissance | T1595.003 (Active Scanning: Wordlist) | nginx probes, scanner-identity rules |
| Initial Access | T1078 (Valid Accounts), T1190 (Exploit Public-Facing App) | cowrie login.success; nginx/dionaea CVE & service probes |
| Execution | T1059 (Command Interpreter), T1204 (User Execution) | cowrie command.input, payload execution |
| Persistence | T1098 (Account Manipulation), T1098.004 (SSH Authorized Keys), T1053.003 (Cron), T1136.001 (Local Account) | authorized_keys implant, crontab, useradd |
| Privilege Escalation | (via account manipulation) | usermod / sudo grant |
| Defense Evasion | T1222.002 (File/Dir Perms Mod), T1070 (Indicator Removal), T1562.001 (Impair Defenses), T1480 (Execution Guardrails), T1036 (Masquerading) | chattr/lockr, log wipe, kill-rival, remount, spoofed-browser scanners |
| Credential Access | T1110 (Brute Force), T1552.001 (Unsecured Credentials) | login.failed/success, `.env` theft, /etc/shadow access |
| Discovery | T1082 (System Info), T1033 (Owner/User), T1057 (Process), T1016 (Network Config), T1518 (Software) | uname, whoami, ps, netstat, which/ssh -V |
| Lateral Movement | T1021.002 (SMB/Windows Admin Shares) | Dionaea SMB |
| Command & Control | T1090 (Proxy), T1105 (Ingress Tool Transfer) | direct-tcpip tunneling, wget/curl, file download, **Dionaea malware capture** |
| Collection | T1213 (Data from Information Repositories) | nginx `.git` exposure |
| Impact | T1496 (Resource Hijacking) | cryptomining recon |

---

## Applying Rule Changes

```bash
# Test a rule against a sample event
/var/ossec/bin/wazuh-logtest      # paste a sample JSON event when prompted

# Apply changes
systemctl restart wazuh-manager
grep -iE "cowrie|dionaea|nginx" /var/ossec/logs/ossec.log | tail -20
```
