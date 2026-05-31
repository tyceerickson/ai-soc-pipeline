# 01 — System Architecture

## Overview

This project implements a full-stack, AI-powered Security Operations Center (SOC) pipeline built on real attack data collected from internet-facing honeypots. The system ingests live attack traffic across three vectors — SSH/Telnet, web, and malware capture — enriches it with geolocation and VirusTotal threat intelligence, indexes it into a SIEM, and surfaces insights through a custom real-time dashboard powered by a local large language model.

The architecture spans three physical machines across two networks, connected via a private mesh VPN (Tailscale).

---

## Infrastructure

### DigitalOcean VPS — `174.138.35.11` (NYC1)
**Role:** Public-facing honeypot host

This server is intentionally exposed to the internet. It runs three containerized honeypots via Docker Compose:

- **Cowrie SSH/Telnet Honeypot** — emulates a vulnerable Linux server on ports 22 and 23. Accepts all credentials, logs every command, captures file uploads and downloads, and records complete session transcripts.
- **nginx** — serves a fake HTTP endpoint to capture web-based scan traffic, CVE probes, and credential-theft attempts against common web paths.
- **Dionaea** — a multi-protocol malware capture honeypot listening on SMB, FTP, MSSQL, MySQL, and other ports to attract and **save** malware drop attempts. Captured binaries are stored on disk (named by MD5) and recorded in Dionaea's SQLite event store.

Every 15 minutes, automation on the VPS syncs collected data to the Ubuntu Server over Tailscale: Cowrie/nginx logs via cron rsync, and the Dionaea SQLite database **plus captured binaries** via a dedicated sync (`sync_dionaea.sh`, run by a systemd timer on the SIEM side). After sync, Cowrie/Dionaea text logs are truncated to prevent disk exhaustion — a hard lesson after a 24-hour disk-full outage on May 24–25, 2026.

**Security posture:** administrative SSH is restricted to port 2222, key-only authentication, Tailscale IP only. The honeypot services are isolated in Docker containers with only their designated ports exposed. (The honeypot SSH on port 22 is the deliberately-exposed sensor; real admin access is the separate 2222 listener.)

---

### Ubuntu Server — `192.168.10.4` (VLAN 10) / `100.82.166.75` (Tailscale)
**Role:** SIEM host, log enrichment engine, AI analysis backend, dashboard backend

This is the core of the SOC pipeline. It runs:

- **Wazuh SIEM** (v4.x) — receives, parses, and indexes all honeypot alerts. Custom rules map honeypot event types to MITRE ATT&CK tactics and assign severity. Wazuh's built-in JSON decoder handles the normalized event format.
- **OpenSearch** — the data store for all Wazuh alerts (index: `wazuh-alerts-4.x-*`). Queried directly by the dashboard backend for real-time aggregations.
- **GeoIP + VirusTotal enrichment** — Python pipeline resolving each attacker IP against MaxMind GeoLite2 (City + ASN), and looking up captured-malware hashes against VirusTotal (hash only — samples are never uploaded). A GeoIP cache is maintained at `/opt/cowrie-logs/geoip_cache.json`.
- **Log parsers** — `parse_nginx.py` (nginx CLF) and `parse_dionaea.py` (Dionaea SQLite → connection/login/malware events with SHA256 + VirusTotal + permanent archive).
- **Flask Dashboard** (`app.py`) — serves the SOC dashboard on port 5000, querying OpenSearch directly over HTTPS for all real-time stats and intelligence panels.
- **Systemd services** — `soc-dashboard.service` keeps the Flask app running; `dionaea-sync.timer` runs the Dionaea sync + parse every 15 minutes. Credentials are supplied via environment variables in the unit files, never hardcoded.

**Automation:**
- Every 15 min: nginx parse (cron) and Dionaea sync + parse (systemd timer)
- Hourly: consolidate rotated Cowrie logs → GeoIP enrichment → rebuild cache
- Every 30 min: AI triage pipeline (summary mode)
- Weekly (Mon 06:00): update MaxMind GeoIP databases

---

### Alienware m16 R2 — `100.72.171.104` (Tailscale)
**Role:** AI inference server

Runs Ollama as a Windows service, serving `llama3.1:8b` on an NVIDIA RTX 4070 (8GB VRAM) over Tailscale. The Ubuntu Server sends structured threat-intelligence prompts to this endpoint and receives natural-language analysis.

**Model:** `llama3.1:8b` — chosen for its balance of reasoning quality and speed on consumer GPU hardware. Summary-mode inference runs in 15–30 seconds. `llama3.3:70b` was tested but rejected: at ~42GB it offloaded heavily from VRAM to system RAM, causing 10+ minute latencies.

---

## Data Flow

```
Internet Attackers
       │
       ▼
[DigitalOcean VPS — NYC1]
  Cowrie SSH/Telnet (port 22/23)
  nginx (port 80/443)
  Dionaea (port 445, 21, 1433, 3306, ...)  ── captures malware binaries
       │
       │  rsync every 15 min (Tailscale): logs + dionaea.sqlite + binaries/
       ▼
[Ubuntu Server — VLAN 10]
  cowrie.json  +  nginx access.log  +  dionaea.sqlite  +  binaries/
       │
       │  parsers + hourly GeoIP enrichment + per-hash VirusTotal lookup
       ▼
  wazuh-*.json  (normalized, enriched)        archive/YYYY-MM/<sha256> (+ .json sidecar)
       │
       │  Wazuh agent reads the JSON feeds
       ▼
  Wazuh SIEM → OpenSearch Index  (wazuh-alerts-4.x-*)
       │
       ├───────────────────────────────────────┐
       ▼                                         ▼
  Flask Dashboard (port 5000)              AI Triage (every 30 min)
  Live OpenSearch queries                  alert_poller.py → ai_triage.py
  12 intelligence panels                   → Ollama (Tailscale) → llama3.1:8b
       │                                    → triage_report.json
       ▼                                         │
  Browser (Tailscale only)                       ▼
  http://100.82.166.75:5000                Dashboard /api/triage
```

---

## Network Security

All dashboard and API access is restricted to the Tailscale mesh VPN. Neither the Wazuh dashboard (443), the SOC dashboard (5000), nor the Ollama API (11434) are reachable from the public internet. Only the honeypot ports on the VPS are intentionally exposed.

Tailscale acts as a zero-trust overlay — each device authenticates with a cryptographic identity before joining the mesh, so no inbound firewall rules need to be opened on the Ubuntu Server for the dashboard to be reachable.

---

## Key Statistics (collection window May 21–29, 2026)

| Metric | Value |
|--------|-------|
| Total Wazuh alerts | 11,611,908 (~11.6M) |
| Cowrie SSH/Telnet events | 872,871 |
| Malware binaries captured | 7 (6 WannaCry + 1 downloader, VirusTotal-verified) |
| Unique attacker IPs | 1,000+ |
| Countries observed | 99 |
| Data gap (disk outage) | May 24 22:12 → May 25 21:39 UTC |
| Active botnets identified | 6 |
| MITRE ATT&CK tactics observed | 7 |
| Peak day (May 23) | 2,019,221 alerts / 24h |
