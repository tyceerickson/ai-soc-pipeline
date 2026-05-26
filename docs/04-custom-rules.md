# 04 — Custom Wazuh Rules & Decoders

## Overview

Wazuh ships with built-in rules for many log sources but has no native support for Cowrie honeypot events. This project adds custom decoders to parse Cowrie's JSON format and custom rules to assign severity levels and MITRE ATT&CK mappings to each event type.

---

## Decoder

Wazuh decoders extract structured fields from raw log lines. Since Cowrie writes JSON, the decoder is straightforward — it uses Wazuh's built-in JSON decoder with field mappings.

### Location: `/var/ossec/etc/decoders/cowrie-decoder.xml`

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

This extracts all JSON fields from the Cowrie log line into Wazuh's `data.*` namespace. Fields like `data.eventid`, `data.src_ip`, `data.username`, `data.password`, `data.input` become available for rule matching and dashboard queries.

---

## Rules

Rules match decoded fields and assign a rule ID, severity level (1-15), description, and optionally MITRE ATT&CK metadata.

### Rule Severity Scale (Wazuh)

| Level | Severity | Description |
|-------|----------|-------------|
| 0-6   | Low      | Informational — session lifecycle, connection events |
| 7-11  | Medium   | Notable — brute force attempts, known bad credentials |
| 12-14 | High     | Serious — successful login, command execution, file activity |
| 15    | Critical | Urgent — SSH key implant, malware upload, persistence established |

### Location: `/var/ossec/etc/rules/cowrie-rules.xml`

```xml
<group name="cowrie,honeypot,">

  <!-- Base rule: any Cowrie event -->
  <rule id="100100" level="3">
    <decoded_as>cowrie-json</decoded_as>
    <field name="data.eventid">cowrie\.</field>
    <description>Honeypot: Cowrie event detected</description>
    <options>no_full_log</options>
    <group>honeypot</group>
  </rule>

  <!-- New connection -->
  <rule id="100101" level="3">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.session.connect</field>
    <description>Honeypot: New SSH connection from $(data.src_ip)</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>honeypot,discovery,</group>
  </rule>

  <!-- SSH key exchange — records attacker client fingerprint -->
  <rule id="100102" level="3">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.client.kex</field>
    <description>Honeypot: SSH key exchange from $(data.src_ip)</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>honeypot,discovery,</group>
  </rule>

  <!-- Failed login -->
  <rule id="100103" level="8">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.login.failed</field>
    <description>Honeypot: Failed login attempt - $(data.username)/$(data.password)</description>
    <mitre>
      <id>T1110</id>
      <id>T1110.001</id>
    </mitre>
    <group>honeypot,credential_access,brute_force,</group>
  </rule>

  <!-- Successful login -->
  <rule id="100104" level="12">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.login.success</field>
    <description>Honeypot: Successful login - $(data.username)/$(data.password) from $(data.src_ip)</description>
    <mitre>
      <id>T1078</id>
      <id>T1110</id>
    </mitre>
    <group>honeypot,credential_access,initial_access,</group>
  </rule>

  <!-- Command execution -->
  <rule id="100105" level="12">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.command.input</field>
    <description>Honeypot: Command executed by attacker: $(data.input)</description>
    <mitre>
      <id>T1059</id>
    </mitre>
    <group>honeypot,execution,</group>
  </rule>

  <!-- File download -->
  <rule id="100106" level="13">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.session.file_download</field>
    <description>Honeypot: File downloaded from attacker: $(data.url)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
    <group>honeypot,execution,command_and_control,</group>
  </rule>

  <!-- File upload (attacker dropping malware) -->
  <rule id="100107" level="14">
    <if_sid>100100</if_sid>
    <field name="data.eventid">cowrie.session.file_upload</field>
    <description>Honeypot: File uploaded by attacker to honeypot</description>
    <mitre>
      <id>T1105</id>
    </mitre>
    <group>honeypot,execution,</group>
  </rule>

  <!-- SSH key implant — mdrfckr botnet signature -->
  <rule id="100108" level="15">
    <if_sid>100105</if_sid>
    <field name="data.input">\.ssh</field>
    <field name="data.input">echo.*ssh-rsa</field>
    <description>Honeypot: SSH authorized_keys implant detected (persistence attempt)</description>
    <mitre>
      <id>T1098.004</id>
      <id>T1098</id>
    </mitre>
    <group>honeypot,persistence,</group>
  </rule>

  <!-- chattr immutable flag — anti-forensics -->
  <rule id="100109" level="14">
    <if_sid>100105</if_sid>
    <field name="data.input">chattr.*-ia</field>
    <description>Honeypot: Attacker set immutable flag on .ssh directory (defense evasion)</description>
    <mitre>
      <id>T1222</id>
    </mitre>
    <group>honeypot,defense_evasion,</group>
  </rule>

  <!-- Privilege escalation attempt -->
  <rule id="100110" level="13">
    <if_sid>100105</if_sid>
    <field name="data.input">sudo|su root|chmod.*777|/etc/passwd</field>
    <description>Honeypot: Privilege escalation attempt by attacker</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>honeypot,privilege_escalation,</group>
  </rule>

</group>
```

---

## MITRE ATT&CK Mapping Summary

| Tactic | Technique | Cowrie Events |
|--------|-----------|---------------|
| Discovery | T1046 — Network Service Scanning | session.connect, client.kex |
| Credential Access | T1110 — Brute Force | login.failed, login.success |
| Credential Access | T1110.001 — Password Guessing | login.failed |
| Initial Access | T1078 — Valid Accounts | login.success |
| Execution | T1059 — Command Interpreter | command.input |
| Persistence | T1098.004 — SSH Authorized Keys | command.input (ssh key pattern) |
| Defense Evasion | T1078 — Valid Accounts | login.success |
| Defense Evasion | T1222 — File Permissions | chattr commands |
| Privilege Escalation | T1078 — Valid Accounts | sudo/su commands |

---

## Applying Rule Changes

After modifying rules or decoders:

```bash
# Test rules syntax
/var/ossec/bin/wazuh-logtest

# Restart manager to apply changes
systemctl restart wazuh-manager

# Verify rules loaded
grep -i "cowrie" /var/ossec/logs/ossec.log | tail -20
```

### Testing a Rule
```bash
/var/ossec/bin/wazuh-logtest
# Paste a sample Cowrie JSON event when prompted
# Output shows which rule matched and at what level
```
