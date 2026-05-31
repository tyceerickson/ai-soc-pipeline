# 09 — Executive Summary

## Project Overview

This project deploys a production-grade, AI-powered Security Operations Center (SOC)
pipeline on real internet infrastructure. **Three honeypots** exposed to the public
internet — Cowrie (SSH/Telnet), nginx (web), and Dionaea (malware capture) — collect
live attack data across distinct vectors. That data is processed through a Wazuh SIEM,
enriched with geolocation and VirusTotal threat intelligence, and analyzed by a
locally-hosted large language model. A custom real-time dashboard provides analysts with
**12 integrated intelligence panels** spanning attack-chain analysis, behavioral botnet
fingerprinting, geographic attribution, session-level kill-chain reconstruction, captured
malware analysis, cross-honeypot threat-actor correlation, and on-demand AI threat briefings.

This is not a simulated lab exercise. Every alert, credential, command, and captured
malware sample in this dataset came from a real attacker on the internet.

## Key Findings

### Scale of Observed Threat Activity

Over the active collection window (**May 21–29, 2026**), the sensors recorded:

- **11,611,908** total security alerts processed by Wazuh SIEM
- **872,871** Cowrie SSH/Telnet events
- **1,000+** unique attacking IP addresses across **99 countries**
- **6** distinct botnet campaigns identified and fingerprinted
- **7** unique malware binaries captured and VirusTotal-verified
- Peak day: ~2.8M alerts in 24 hours

The attack surface was a small set of exposed services on a single VPS. The volume represents the baseline threat level any internet-connected system faces — on the order of 20+ attack events per second at sustained volume.

### Live Malware Capture — WannaCry Still Propagating

The Dionaea honeypot captured **7 unique malware binaries** delivered over SMB, each
hash-verified against VirusTotal:

- **6 of 7 samples were WannaCry ransomware variants** (59–66 of ~76 VirusTotal engines
  flagging each), the remaining sample a trojan downloader
- Delivered from source IPs across **multiple countries** (United States, Thailand,
  Sri Lanka, Vietnam) — independent infections all blindly scanning for exposed SMB
- Each sample is SHA256-hashed, attributed to its source IP/country/service, and preserved
  in a permanent read-only archive with metadata

WannaCry continuing to self-propagate over exposed SMB years after its 2017 outbreak is a
concrete, measurable illustration of long-tail internet threat activity — and of why
legacy-protocol exposure remains a live risk.

### Two Major Attack Waves

- **Wave 1 — May 22 (~1.3M alerts/24h):** the `345gs5662d34` credential-stuffing campaign.
  `root/345gs5662d34` was attempted **103,084 times across 357 unique IPs** — a coordinated
  multi-source effort and the largest single-credential campaign in the dataset.
- **Wave 2 — peak day (~2.8M alerts/24h):** the `mdrfckr` botnet at peak activity,
  combining the credential sweep with a full SSH key-implant playbook on every successful
  session.

### The mdrfckr Botnet

The most sophisticated campaign observed:

- **Signature:** an SSH public key ending in `mdrfckr` implanted via `~/.ssh/authorized_keys`
- **Anti-forensics:** uses `chattr -ia` to set the immutable flag on `.ssh`, preventing key
  removal even by root
- **Scale:** ~90,000 key-implant attempts across the window
- **Infrastructure:** routes through distributed VPN nodes to evade IP-based blocking
- **Objective:** persistent, removal-resistant backdoor access to Linux servers

### nginx Web Honeypot

Within days of deployment, the web honeypot logged requests probing hundreds of unique
paths: IoT botnet activity, `.env` credential theft targeting SendGrid/Twilio API keys,
Hikvision CVE-2021-36260 RCE probes, TP-Link firmware exploits (CVE-2021-22161), and Tomcat
manager brute-force.

### Cross-Vector Threat Actors

The Threat Actor Correlation analysis unifies each source IP's activity across all three
honeypots into a single threat-scored profile. Multiple IPs were observed attacking more
than one honeypot — e.g. brute-forcing SSH *and* delivering malware over SMB — revealing
coordinated actors that siloed per-sensor views would miss.

## Technical Architecture

| Component | Machine | Role |
|-----------|---------|------|
| Cowrie / nginx / Dionaea honeypots | DigitalOcean VPS (NYC1) | Internet-facing attack collection |
| Wazuh SIEM + OpenSearch | Ubuntu Server (aarch64) | Indexing, alerting, enrichment |
| Flask SOC Dashboard | Ubuntu Server | Real-time visualization |
| LLM inference (Ollama + llama3.1:8b) | Alienware m16 R2 (RTX 4070) | AI threat analysis |

All internal communication uses the Tailscale encrypted mesh VPN. The dashboard and API are
not accessible from the public internet. Credentials are supplied via environment variables,
not stored in source.

**Technology stack:** Python, Flask, OpenSearch, Wazuh 4.x, Cowrie, nginx, Dionaea, Docker,
Tailscale, rsync, MaxMind GeoLite2, VirusTotal API, Ollama, llama3.1:8b, HTML5 Canvas,
Natural Earth geodata.

## Security Capabilities Demonstrated

1. **Real-time SIEM operations** — custom decoders/rules, MITRE ATT&CK mapping, 11M+ alerts
   indexed with sub-second query response.
2. **Behavioral threat intelligence** — botnets identified by behavioral signature
   (credentials, commands, SSH keys), more durable than IP-based detection as infrastructure rotates.
3. **Live malware capture & verification** — real binaries captured, SHA256-hashed,
   VirusTotal-verified, attributed, and permanently archived (hash-only lookups; samples never leave the network).
4. **AI-augmented analysis** — a local LLM produces structured threat assessments and
   CISO-ready briefings in seconds from pre-aggregated context; no data leaves the network.
5. **Geographic attribution** — 99 countries via MaxMind GeoLite2 on a Natural Earth map.
6. **Kill-chain & cross-vector reconstruction** — full session reconstruction plus unified
   per-IP threat-actor profiles across all three honeypots.

## Skills Demonstrated

Linux system administration (systemd, cron, disk management) · network security (Tailscale
VPN, SSH hardening, Docker isolation) · SIEM deployment & custom rule development · data
engineering (collection, transport, GeoIP/VT enrichment, schema design) · Python development
(Flask REST API, OpenSearch queries, SQLite parsing) · frontend development (HTML5 Canvas
visualization) · AI/ML integration (local LLM, prompt engineering) · threat intelligence
(botnet fingerprinting, malware analysis, MITRE mapping) · secure secrets handling
(environment-based credentials, key rotation discipline).

## Relevance to Information Security Policy & Management

- **Risk management:** quantifies actual exposure (1,000+ attackers, 99 countries, 6
  botnets, live ransomware capture) — concrete data rather than theoretical modeling.
- **Security operations:** an end-to-end sensor-to-dashboard pipeline mirroring enterprise
  SOC architecture, with AI triage addressing analyst alert fatigue.
- **Policy implications:** anti-forensic techniques, VPN obfuscation, and the persistence of
  legacy-protocol malware illustrate the attacker/defender sophistication gap relevant to
  security program design.
- **Executive communication:** the AI executive-summary mode bridges technical operations
  and organizational leadership — a core MSISPM competency.

---

*Built as Project 4 of 4 for a CMU MSISPM application portfolio. All data collected from
real internet attack traffic on infrastructure owned and operated by the author.*
