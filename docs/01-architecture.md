# 01 — System Architecture

## Overview

This project implements a full-stack, AI-powered Security Operations Center (SOC) pipeline built on real attack data collected from an internet-facing honeypot. The system ingests live SSH attack traffic, enriches it with geolocation and threat intelligence, indexes it into a SIEM, and surfaces insights through a custom real-time dashboard powered by a local large language model.

The architecture spans three physical machines across two networks, connected via a private mesh VPN (Tailscale).

---

## Infrastructure

### DigitalOcean VPS — `174.138.35.11` (NYC1)
**Role:** Public-facing honeypot host

This server is intentionally exposed to the internet. It runs three containerized honeypots via Docker Compose:

- **Cowrie SSH/Telnet Honeypot** — emulates a vulnerable Linux server on port 22 and 23. Accepts all credentials, logs every command, captures file uploads and downloads, and records complete session transcripts.
- **Nginx** — serves a fake HTTP endpoint to capture web-based scan traffic and credential stuffing attempts against common web paths.
- **Dionaea** — a multi-protocol malware capture honeypot that listens on SMB, FTP, HTTP, and other common ports to attract and record malware drop attempts.

Every 15 minutes, a cron job on the VPS rsyncs all collected logs to the Ubuntu Server over Tailscale. After sync, Cowrie logs are truncated to prevent disk exhaustion (a hard lesson learned after a 24-hour disk-full outage on May 24-25, 2026).

**Security posture:** SSH access is restricted to port 2222, key-only authentication, and Tailscale IP only. Fail2ban is active. The honeypot services are isolated in Docker containers with no host network access beyond their designated ports.

---

### Ubuntu Server — `192.168.10.4` (VLAN 10) / `100.82.166.75` (Tailscale)
**Role:** SIEM host, log enrichment engine, AI analysis server, dashboard backend

This is the core of the SOC pipeline. It runs:

- **Wazuh SIEM** (v4.x) — receives, parses, and indexes all honeypot alerts. Custom rules map Cowrie event types to MITRE ATT&CK tactics and assign severity levels. Wazuh's built-in decoders handle Cowrie's JSON log format.
- **OpenSearch** — the underlying data store for all Wazuh alerts (index: `wazuh-alerts-4.x-*`). Queried directly by the dashboard backend for real-time aggregations.
- **GeoIP Enrichment Pipeline** — a Python script (`enrich_logs.py`) that reads consolidated Cowrie logs, resolves each attacker IP against MaxMind GeoLite2 databases (City + ASN), and writes enriched JSON. A cache of 944 fully-resolved IPs is maintained at `/opt/cowrie-logs/geoip_cache.json`.
- **Flask Dashboard** (`app.py`) — serves the SOC dashboard web application on port 5000. Queries OpenSearch directly via HTTPS for all real-time stats, aggregations, and intelligence panels.
- **Systemd Service** (`soc-dashboard.service`) — keeps the Flask app running continuously, auto-restarts on failure.

**Automation:**
- Hourly cron: consolidate rotated Cowrie log files → run GeoIP enrichment → rebuild cache
- Every 30 minutes: run AI triage pipeline (summary mode)
- Weekly Monday 6am: update MaxMind GeoIP databases

---

### Alienware m16 R2 — `100.72.171.104` (Tailscale)
**Role:** AI inference server

Runs Ollama as a Windows service, serving `llama3.1:8b` on an NVIDIA RTX 4070 (8GB VRAM) over the Tailscale network. The Ubuntu Server sends structured threat intelligence prompts to this endpoint and receives natural-language analysis in response.

**Model:** `llama3.1:8b` — chosen for its balance of reasoning quality and speed on consumer GPU hardware. Full inference runs in 15-30 seconds for summary mode. `llama3.3:70b` was tested but rejected due to excessive RAM offload (42GB) causing unacceptable latency.

---

## Data Flow

```
Internet Attackers
       │
       ▼
[DigitalOcean VPS — NYC1]
  Cowrie SSH Honeypot (port 22/23)
  Nginx (port 80/443)
  Dionaea (port 445, 21, etc.)
       │
       │  rsync every 15 min (Tailscale)
       ▼
[Ubuntu Server — VLAN 10]
  cowrie.json (consolidated raw logs)
       │
       │  hourly: enrich_logs.py
       ▼
  cowrie_enriched.json (with GeoIP)
       │
       │  Wazuh agent reads enriched logs
       ▼
  Wazuh SIEM → OpenSearch Index
  wazuh-alerts-4.x-*
       │
       ├──────────────────────────────────┐
       │                                  │
       ▼                                  ▼
  Flask Dashboard (port 5000)       AI Triage (every 30 min)
  Live queries to OpenSearch        alert_poller.py
  8 intelligence panels             → alerts_raw.json
  Real-time stats + aggregations    → ai_triage.py
       │                            → Ollama (Tailscale)
       │                            → llama3.1:8b on RTX 4070
       ▼                            → triage_report.json
  Browser (Tailscale only)               │
  http://100.82.166.75:5000              ▼
                                    Dashboard /api/triage
```

---

## Network Security

All dashboard and API access is restricted to the Tailscale mesh VPN. Neither the Wazuh dashboard (port 443) nor the SOC dashboard (port 5000) nor the Ollama API (port 11434) are accessible from the public internet. Only the honeypot ports on the VPS are intentionally exposed.

Tailscale acts as a zero-trust overlay network — each device authenticates with a cryptographic identity before joining the mesh. No firewall rules need to be opened on the Ubuntu Server for the dashboard to be reachable.

---

## Key Statistics (as of May 26, 2026)

| Metric | Value |
|--------|-------|
| Total Wazuh alerts | 6,185,397 |
| Cowrie SSH events | 218,392 |
| Unique attacker IPs | 944 |
| Countries observed | 99 |
| Collection period | May 19 – May 26, 2026 |
| Data gap (disk outage) | May 24 22:12 → May 25 21:39 UTC |
| Active botnets identified | 6 |
| MITRE ATT&CK tactics observed | 7 |
