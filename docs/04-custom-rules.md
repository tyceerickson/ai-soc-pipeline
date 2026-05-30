# 04 — Custom Wazuh Rules & Decoders

## Overview

Wazuh ships with built-in rules for many log sources but has no native support for honeypot events. This project adds custom decoders to parse the honeypot JSON formats and custom rules to assign severity and MITRE ATT&CK mappings. Two rule files are used:

- `config/wazuh-cowrie-rules.xml` — Cowrie SSH/Telnet (IDs **100100–100110**)
- `config/wazuh-honeypot-web-rules.xml` — Dionaea + nginx (IDs **100200–100360**)

> The rule snippets below are illustrative of structure and intent. The authoritative, current rule definitions live in the two XML files in `config/` (most recently hardened to fix regex edge cases and tune brute-force frequency thresholds).

---

## Decoder

Since the honeypots emit JSON, the decoder uses Wazuh's built-in JSON decoder with a prematch.

### `/var/ossec/etc/decoders/cowrie-decoder.xml`
```xml
<decoder name="cowrie">
  <prematch>{"eventid": "cowrie.</prematch>
</decoder>

<decoder name="cowrie-json">
  <parent>cowrie</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
  <use_own_name>true</use_own_name>
  <json_null_field>discard</json_null_field>
  <var name="NET_PREFIX">data.</var>
</decoder>
```

This extracts all JSON fields into Wazuh's `data.*` namespace (`data.eventid`, `data.src_ip`, `data.username`, `data.password`, `data.input`, `data.sha256`, etc.) for rule matching and dashboard queries. The Dionaea and nginx events use the same JSON-decoder approach keyed on their respective `data.eventid` / `data.honeypot` values.

---

## Rule Severity Scale (Wazuh)

| Level | Severity | Description |
|-------|----------|-------------|
| 0–6   | Low      | Informational — session lifecycle, connection events |
| 7–11  | Medium   | Notable — brute-force attempts, scanning, known-bad credentials |
| 12–14 | High     | Serious — successful login, command execution, **malware capture** |
| 15    | Critical | Urgent — SSH key implant, persistence established |

---

## Cowrie Rules (illustrative — see `config/wazuh-cowrie-rules.xml`)

```xml
<group name="cowrie,honeypot,">

  <rule id="100100" level="3">
    <decoded_as>cowrie-json</decoded_as>
    <field name="data.eventid">cowrie\.</field>
    <description>Honeypot: Cowrie event detected</description>
  </rule>

  <rule id="100101" level="3">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.session.connect</field>
    <description>Honeypot: New SSH connection from $(data.src_ip)</description>
    <mitre><id>T1046</id></mitre>
  </rule>

  <rule id="100103" level="8">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.login.failed</field>
    <description>Honeypot: Failed login - $(data.username)/$(data.password)</description>
    <mitre><id>T1110</id><id>T1110.001</id></mitre>
  </rule>

  <rule id="100104" level="12">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.login.success</field>
    <description>Honeypot: Successful login - $(data.username)/$(data.password) from $(data.src_ip)</description>
    <mitre><id>T1078</id><id>T1110</id></mitre>
  </rule>

  <rule id="100105" level="12">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.command.input</field>
    <description>Honeypot: Command executed: $(data.input)</description>
    <mitre><id>T1059</id></mitre>
  </rule>

  <!-- SSH key implant — mdrfckr botnet signature -->
  <rule id="100108" level="15">
    <if_sid>100105</if_sid>
    <field name="data.input">authorized_keys</field>
    <description>Honeypot: SSH authorized_keys implant detected (persistence)</description>
    <mitre><id>T1098.004</id><id>T1098</id></mitre>
  </rule>

  <!-- chattr immutable flag — anti-forensics -->
  <rule id="100109" level="14">
    <if_sid>100105</if_sid>
    <field name="data.input">chattr.*-ia</field>
    <description>Honeypot: Immutable flag set on .ssh (defense evasion)</description>
    <mitre><id>T1222</id></mitre>
  </rule>

  <!-- Brute-force frequency rule (10+ attempts) -->
  <rule id="100110" level="10" frequency="10" timeframe="120">
    <if_matched_sid>100103</if_matched_sid>
    <same_field>data.src_ip</same_field>
    <description>Honeypot: SSH brute force — 10+ attempts from $(data.src_ip)</description>
    <mitre><id>T1110</id></mitre>
  </rule>

</group>
```

---

## Dionaea + nginx Rules (see `config/wazuh-honeypot-web-rules.xml`, IDs 100200–100360)

Highlights:

| Rule | Level | Event | MITRE |
|------|-------|-------|-------|
| Dionaea connection (SMB/FTP/MSSQL/MySQL) | 3 | `dionaea.connection.*` | T1046 |
| Dionaea login attempt | 6 | `dionaea.login.*` | T1110 |
| **Dionaea malware binary captured** | **12** | `dionaea.binary.captured` | **T1105** |
| nginx scan / probe | 5–8 | `nginx.*` | T1595 |
| nginx CVE probe (Hikvision, TP-Link, Tomcat, Log4Shell) | 10–12 | `nginx.*` | T1190 |
| nginx `.env` / credential-theft path | 10 | `nginx.*` | T1552 |

The `dionaea.binary.captured` rule carries the SHA256, source IP, service, and (when enriched) the VirusTotal verdict, surfacing each real malware capture as a High-severity alert.

---

## MITRE ATT&CK Mapping Summary

| Tactic | Technique | Source |
|--------|-----------|--------|
| Reconnaissance | T1595 — Active Scanning | nginx probes |
| Discovery | T1046 — Network Service Scanning | connect, kex, Dionaea connections |
| Initial Access | T1190 — Exploit Public-Facing App | nginx CVE probes |
| Initial Access | T1078 — Valid Accounts | login.success |
| Credential Access | T1110 / T1110.001 — Brute Force | login.failed/success |
| Credential Access | T1552 — Unsecured Credentials | nginx `.env` theft |
| Execution | T1059 — Command Interpreter | command.input |
| Persistence | T1098.004 — SSH Authorized Keys | key implant |
| Defense Evasion | T1222 — File Permissions | chattr commands |
| Command & Control | T1105 — Ingress Tool Transfer | file download, **Dionaea malware capture** |

---

## Applying Rule Changes

```bash
# Test a rule against a sample event
/var/ossec/bin/wazuh-logtest      # paste a sample JSON event when prompted

# Apply changes
systemctl restart wazuh-manager
grep -iE "cowrie|dionaea|nginx" /var/ossec/logs/ossec.log | tail -20
```
