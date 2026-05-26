# 09 — Executive Summary

## Project Overview

This project deploys a production-grade, AI-powered Security Operations Center pipeline on real internet infrastructure. An SSH honeypot exposed to the public internet collects live attack data which is processed through a SIEM, enriched with threat intelligence, and analyzed by a locally-hosted large language model. A custom real-time dashboard provides security analysts with 8 integrated intelligence panels covering attack chain analysis, behavioral botnet fingerprinting, geographic attribution, session-level kill chain reconstruction, and on-demand AI threat briefings.

**This is not a simulated lab exercise. Every alert, every credential, every command in this dataset came from a real attacker on the internet.**

---

## Key Findings

### Scale of Observed Threat Activity

Over 7 days of active collection (May 19-26, 2026), the honeypot received:

- **6,185,397 total security alerts** processed by Wazuh SIEM
- **218,392 individual Cowrie SSH events** logged
- **944 unique attacking IP addresses** across **99 countries**
- **13,801 High-severity alerts** including successful logins and command execution
- **6 distinct botnet campaigns** identified and fingerprinted

The attack surface was a single server with a single open SSH port. The volume of attack traffic represents the baseline threat level that any internet-connected system faces.

### Two Major Attack Waves

Analysis of the alert timeline reveals two distinct surge events:

**Wave 1 — May 22, ~1.3M alerts in 24 hours**
The first major botnet campaign involving the 345gs5662d34 credential campaign. The credential `root/3245gs5662d34` was used 103,084 times across 357 unique IPs — a coordinated multi-source campaign probing for vulnerable SSH servers.

**Wave 2 — May 23, ~2M alerts in 24 hours (peak: 2,019,221)**
The largest attack period, driven by the mdrfckr botnet reaching peak activity. This campaign not only used the 345gs5662d34 credential but also executed a complete SSH key implant playbook on every successful session — establishing persistent backdoor access.

### The mdrfckr Botnet

The most sophisticated campaign observed. Characteristics:
- **Signature:** SSH public key ending in `mdrfckr` implanted via `~/.ssh/authorized_keys`
- **Anti-forensics:** Uses `chattr -ia` to set immutable flag on `.ssh` directory, preventing key removal even by root
- **Scale:** 90,529 key implant attempts across 7 days
- **Infrastructure:** Routes through Pfcloud UG VPN nodes in Bulgaria, Netherlands, Germany — geographically distributed to evade IP-based blocking
- **Objective:** Persistent backdoor access to compromised Linux servers, likely for use as botnet nodes or cryptomining infrastructure

On a real production server this attack would result in a persistent, removal-resistant backdoor that survives password changes.

### Attack Chain Analysis

Of all connections observed:
- **45%** completed SSH key exchange (others are blind port scanners)
- **27%** attempted credential authentication (reached the login prompt)
- **17%** "succeeded" (Cowrie accepted all credentials by design)
- **19%** executed commands after login
- **7%** downloaded files from attacker-controlled servers
- **0.2%** uploaded files to the honeypot

The 109% command-to-login ratio (more commands than logins) indicates that successful attackers ran multiple commands per session — the average compromised session involved 3-5 commands.

---

## Technical Architecture

The pipeline spans three physical machines:

| Component | Machine | Role |
|-----------|---------|------|
| Cowrie Honeypot | DigitalOcean VPS (NYC1) | Internet-facing attack collection |
| Wazuh SIEM + OpenSearch | Ubuntu Server (VLAN 10) | Indexing, alerting, enrichment |
| Flask Dashboard | Ubuntu Server | Real-time visualization |
| LLM Inference | Alienware m16 R2 | AI threat analysis |

All internal communication uses Tailscale encrypted mesh VPN. The dashboard and API are not accessible from the public internet.

**Technology stack:** Python, Flask, OpenSearch, Wazuh 4.x, Cowrie, Docker, Nginx, Dionaea, Tailscale, Ollama, llama3.1:8b, HTML5 Canvas, Natural Earth geodata.

---

## Security Capabilities Demonstrated

### 1. Real-Time SIEM Operations
Wazuh processes honeypot events in real time, applies custom decoders and rules, maps events to MITRE ATT&CK, and indexes 6M+ alerts with sub-second query response via OpenSearch.

### 2. Behavioral Threat Intelligence
Botnet campaigns are identified not by IP address but by behavioral signatures — the specific credentials, commands, and SSH keys they use. This approach is more durable than IP-based detection because it remains effective even as botnets rotate their infrastructure.

### 3. AI-Augmented Analysis
A locally-hosted LLM (`llama3.1:8b` on RTX 4070) produces structured threat assessments, attacker profiles, and CISO-ready executive summaries in 15-30 seconds. The model receives pre-aggregated statistical context enabling it to reason about the full 6M-alert dataset rather than just a small sample. No data leaves the internal network.

### 4. Geographic Attribution
99 attacker countries identified via MaxMind GeoLite2 and visualized on a Natural Earth 50m world map. Top source countries: Indonesia (897K alerts), United States (758K), Netherlands (565K), Bulgaria (471K), Germany (469K).

### 5. Kill Chain Reconstruction
The Session Depth Analyzer reconstructs complete attacker sessions — from initial connection through credential attempt, command execution, file download, and key implant — mapping each event to its MITRE ATT&CK technique. This enables understanding not just that an attack occurred but exactly what the attacker did.

---

## Skills Demonstrated

This project required and demonstrates proficiency in:

- **Linux system administration** — Ubuntu Server, systemd services, cron automation, disk management
- **Network security** — VPN configuration (Tailscale), SSH hardening, firewall rules, Docker isolation
- **SIEM deployment and operation** — Wazuh installation, custom rule and decoder development, OpenSearch query optimization
- **Data engineering** — Log collection, transport (rsync), transformation (GeoIP enrichment), storage design
- **Python development** — Flask REST API, OpenSearch client, subprocess orchestration, JSON processing
- **Frontend development** — HTML5 Canvas, data visualization, responsive dashboard design
- **AI/ML integration** — Local LLM deployment (Ollama), prompt engineering, structured output parsing
- **Threat intelligence** — Botnet fingerprinting, behavioral IOC development, MITRE ATT&CK mapping
- **Incident analysis** — Kill chain reconstruction, attacker profiling, executive reporting

---

## Relevance to Information Security Policy & Management

This project directly addresses core MSISPM curriculum themes:

**Risk Management:** The project quantifies actual threat exposure — 944 unique attackers, 99 countries, 6 active botnets — providing concrete data for risk assessment rather than theoretical threat modeling.

**Security Operations:** The end-to-end pipeline from sensor to dashboard mirrors enterprise SOC architecture. The AI triage capability addresses analyst alert fatigue, a critical challenge in modern security operations.

**Policy Implications:** The mdrfckr campaign's use of anti-forensic techniques (`chattr -ia`) and VPN infrastructure for geographic obfuscation illustrates the sophistication gap between attackers and defenders, directly relevant to security program design.

**Executive Communication:** The Executive analysis mode produces CISO-ready briefings from raw technical data, bridging the gap between security operations and organizational leadership — a core MSISPM competency.
