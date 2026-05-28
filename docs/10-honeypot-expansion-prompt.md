# 10 — Continuation Prompt: Add Dionaea + nginx Honeypot Panels

## Context for new thread

This document is the exact prompt to paste into a new Claude thread to add Dionaea malware and nginx web honeypot panels to the existing SOC dashboard.

---

## Paste this prompt into a new thread:

---

I'm building a CMU MSISPM portfolio SOC dashboard (Project 4: AI-Powered SOC Pipeline). I need to add two new honeypot data panels to an existing, working Flask dashboard. Here is the complete context you need.

## Infrastructure

- **Alienware m16 R2** (primary, Windows 11, Tailscale: 100.72.171.104) — where I run git/scp
- **Ubuntu Server** (192.168.10.4, Tailscale: 100.82.166.75) — runs the Flask dashboard at port 5000, has Wazuh SIEM
- **DigitalOcean VPS** (NYC1, Tailscale: 100.89.15.57) — internet-facing honeypot server
- SSH: `ssh -p 2222 root@100.89.15.57` (Tailscale key auth)
- Ubuntu server SSH: `ssh homeserver` (alias from Alienware)

## Current Dashboard State

The dashboard is fully working at `http://100.82.166.75:5000`. It currently shows:
- Live Alert Summary (severity cards)
- Alert Timeline (clickable spikes → event breakdown modal)
- Top Attacker Countries + Geographic Map
- Attack Velocity (60-min spark)
- Attack Chain Funnel + Attack Heatmap
- Botnet Fingerprints (auto-detected, All/7d/24h selectors)
- Top Credentials + Credential Intelligence
- Top Commands Executed + Attacker Intelligence
- MITRE ATT&CK Framework (dynamic, all tactics)
- On-Demand AI Analysis (Ollama llama3.1:8b)
- Status bar (OpenSearch health, GeoIP count, refresh time)

Backend: `app.py` (Flask, 1733 lines) at `/opt/wazuh-soc/dashboard/app.py`
Frontend: `index.html` at `/opt/wazuh-soc/dashboard/templates/index.html`
GitHub: `https://github.com/tyceerickson/ai-soc-pipeline`
Service: `soc-dashboard.service` (systemd, User=terickson)

**IMPORTANT:** The dashboard currently only shows Cowrie SSH honeypot data. Dionaea and nginx are running but NOT yet integrated.

## The Problem

Three Docker services run on the VPS:
1. **Cowrie** (SSH/Telnet) — already integrated ✅
2. **Dionaea** (malware/exploit honeypot: FTP, SMB, MSSQL, MySQL, HTTP exploits) — NOT integrated ❌
3. **nginx** (HTTP web honeypot/decoy) — NOT integrated ❌

The rsync pipeline only ships Cowrie logs. Dionaea and nginx logs exist on the VPS but never reach Wazuh/OpenSearch.

## VPS Honeypot File Locations

Check these on the VPS (`ssh -p 2222 root@100.89.15.57`):
```bash
# Cowrie (already working)
/opt/honeypot/cowrie/cowrie-git/var/log/cowrie/cowrie.json.*

# Dionaea (needs integration)
/opt/honeypot/dionaea/var/log/dionaea/        # connection logs
/opt/honeypot/dionaea/var/lib/dionaea/bistreams/  # captured binaries
/opt/honeypot/dionaea/var/log/dionaea.json    # JSON event log (if configured)

# nginx (needs integration)  
/var/log/nginx/access.log
/var/log/nginx/error.log
# OR Docker volume:
/opt/honeypot/nginx/logs/access.log
```

First verify what actually exists, then proceed.

## What I Need Built

### Phase 1: Data Pipeline (VPS → Ubuntu Server → Wazuh)

1. **Add Dionaea logs to rsync** — update `/etc/cron.d/cowrie-sync` on the VPS to also sync Dionaea JSON logs to Ubuntu Server at `/opt/cowrie-logs/dionaea/`

2. **Add nginx logs to rsync** — sync nginx access.log to `/opt/cowrie-logs/nginx/`

3. **Write Wazuh decoders** for both:
   - Dionaea: JSON format, extract `src_host`, `dst_port`, `service`, `sha256` (malware hash)
   - nginx: standard access log format (IP, method, path, status, user-agent)

4. **Write Wazuh rules** for both that generate alerts with `data.honeypot: dionaea` and `data.honeypot: nginx` fields so the existing dashboard filter `{"exists": {"field": "data.honeypot"}}` picks them up

5. **Verify alerts appear in OpenSearch** before touching the dashboard

### Phase 2: Dashboard — One New Combined Panel OR Two Separate Panels

Add a **"Multi-Honeypot Intelligence"** section to the dashboard with:

#### Dionaea Malware Panel
- Total connections by service (FTP, SMB, MSSQL, MySQL, HTTP)
- Top source IPs (with GeoIP)
- Malware binaries captured: filename, SHA256 hash, size, first/last seen
- Top exploit types attempted
- Timeline of exploit activity
- Click to get AI analysis of a specific binary/service

#### nginx Web Honeypot Panel  
- Top requested paths (scanning patterns, CVE probes)
- HTTP method breakdown (GET/POST/HEAD)
- Top user agents (scanner identification: Shodan, Censys, Mirai variants)
- Response code distribution
- Timeline of web scanning activity
- Click to get AI analysis of scanning campaign

### Design Requirements
- Same winter mountain forest theme (CSS variables: `--bg`, `--bark`, `--forest`, `--text`, etc.)
- Same panel style (`.panel`, `.panel-hdr`, `.panel-title`)
- Same ⓘ tooltip pattern for labels
- Add to existing `app.py` as new API endpoints: `/api/dionaea` and `/api/nginx`
- Add panels to existing `index.html` after the MITRE section
- Maintain all existing functionality

## Files to Fetch from GitHub

Before starting, fetch the current versions:
```
https://raw.githubusercontent.com/tyceerickson/ai-soc-pipeline/main/dashboard/app.py
https://raw.githubusercontent.com/tyceerickson/ai-soc-pipeline/main/dashboard/templates/index.html
```

## Current Alert Index

OpenSearch index: `wazuh-alerts-4.x-*`
Credentials (Ubuntu Server internal): admin / BJ6xeV2bh?NgSvSPPWBwU+IqRzD6HmJj
URL: https://localhost:9200

## Key Patterns Already in app.py to Follow

```python
# All honeypot queries use this filter pattern:
{"exists": {"field": "data.honeypot"}}

# For Dionaea, add:
{"term": {"data.honeypot": "dionaea"}}

# For nginx, add:
{"term": {"data.honeypot": "nginx"}}

# Parallel queries use ThreadPoolExecutor(max_workers=8)
# Results cached with @cached(ttl_seconds=300)
# Rate limited with @rate_limit(max_per_minute=10)
```

## Deployment Pattern

```bash
# After editing, deploy from Alienware:
scp app.py terickson@100.82.166.75:/opt/wazuh-soc/dashboard/app.py
scp index.html terickson@100.82.166.75:/opt/wazuh-soc/dashboard/templates/index.html
sudo systemctl restart soc-dashboard

# Git commit from Alienware:
cd C:\TyceErickson\Projects\ai-soc-pipeline
git add dashboard/app.py dashboard/templates/index.html
git commit -m "M15: Add Dionaea and nginx honeypot panels"
git pull origin main --rebase
git push origin main
```

## Start Here

1. SSH to VPS and check what Dionaea/nginx log files actually exist and their format
2. Check if Dionaea is configured to write JSON logs or only sqlite
3. Report what you find before writing any code
4. Then proceed with Phase 1 (pipeline), verify data flows, then Phase 2 (dashboard)

Do NOT touch the existing Cowrie pipeline or dashboard functionality.

---

End of continuation prompt.
