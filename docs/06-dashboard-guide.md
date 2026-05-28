# 06 — Dashboard Guide

## Overview

The SOC dashboard is a custom Flask web application (`app.py`, v6) that provides real-time visibility into Cowrie SSH honeypot attack data. It queries OpenSearch (Wazuh) directly for live statistics, renders 10+ intelligence panels, and integrates with Ollama llama3.1:8b for on-demand threat analysis. Accessible at `http://100.82.166.75:5000` via Tailscale.

**Important — Data Source Clarification:**
The dashboard currently visualizes **Cowrie SSH/Telnet honeypot data only**. Dionaea (malware/exploit honeypot) and nginx (HTTP honeypot) are running in Docker on the VPS but their logs are not yet synced to the Ubuntu Server or indexed in Wazuh. Adding those is planned for a future session. Everything below describes Cowrie-sourced data.

---

## Alert Source Explained

This is the most important section to understand before interpreting any panel.

### Where alerts come from
Every number in the dashboard comes from **Wazuh OpenSearch** at `wazuh-alerts-4.x-*`. Wazuh receives logs forwarded from the Ubuntu Server (which receives them from the VPS via rsync every 15 minutes). The log flow is:

```
VPS (Cowrie) → rsync → Ubuntu Server → Wazuh → OpenSearch → Dashboard
```

### What is a "Wazuh alert"?
A Wazuh alert is a **rule violation event** that Wazuh's rule engine generates when it sees a log line matching a pattern. One Cowrie event (e.g., a login attempt) can generate multiple Wazuh alerts if it matches multiple rules. This is why raw alert counts are always higher than raw session or event counts.

All dashboard queries filter `{"exists": {"field": "data.honeypot"}}` to limit to honeypot-tagged alerts only.

### Why Top Attacker Countries and Geographic Map show different numbers

| Panel | Data source | What it counts |
|-------|-------------|----------------|
| Top Attacker Countries | `data.location.country_name` field from OpenSearch aggregation | Total Wazuh rule violation events per country — includes all severity levels |
| Geographic Attack Map | `top_ips` list — per-IP alert counts, then summed by country | Uses GeoIP-resolved IPs only; IPs without GeoIP resolution are excluded |

The difference: Countries bar chart counts ALL alerts including those without GeoIP (Wazuh's built-in location field). The map only shows countries where `geoip_cache.json` has a match for the source IP. IPs not yet in the GeoIP cache show "resolving..." and don't appear on the map.

---

## Panel Reference

### Live Alert Summary
Five cards: Total, Critical (L15+), High (L12–14), Medium (L7–11), Low (L0–6).
**Source:** Main OpenSearch aggregation on `rule.level` ranges.
**Why these levels:** Wazuh severity levels 0–15, mapped to severity buckets that match the risk of the underlying Cowrie event type.

### Alert Timeline
Canvas chart. Click any spike to open the **Spike Detail Modal** showing MITRE tactics, countries, campaigns, and top IPs active in that exact time bucket.
**Source:** Date histogram aggregation from OpenSearch. Bucket sizes: 5m (≤2h window), 15m (≤6h), 30m (≤12h), 1h (≤24h), 2h (≤3d), 6h (≤7d), 12h (≤30d), 1d (>30d).
**Accuracy note:** Click precision matches the bucket size — on a 7-day view each click covers a 6-hour window.

### Top Attacker Countries
Horizontal bar chart, top 20 countries by Wazuh alert volume.
**Source:** `data.location.country_name` aggregation. Includes all alerts.

### Geographic Attack Map
World map with red attack dots sized by alert volume.
**Source:** `top_ips` list filtered to IPs with GeoIP resolution. Countries without matched IPs are excluded.

### Top Attacker IPs
Table of source IPs ranked by alert count.
**Source:** `data.src_ip` terms aggregation, top 2000. GeoIP enriched from `geoip_cache.json`.

### Attack Velocity
Live 60-minute spark chart showing attacks-per-minute. Hover any bar for exact count and time.
**Source:** `/api/velocity` — 1-minute bucket date histogram over last 60 minutes.
**Polling:** Updates every 30 seconds.

### Event Types
Bar chart of Cowrie event IDs (cowrie.login.failed, cowrie.command.input, cowrie.session.connect, etc.).
**Source:** `data.eventid` terms aggregation.

### Attack Chain Funnel
Kill chain progression showing how many attackers made it through each stage.
Stages: Session Connect → SSH Key Exchange → Login Failed → Login Success → Command Executed → File Downloaded → File Uploaded.
**Source:** Separate count queries per eventid type.

### Attack Heatmap
14-day, 24-hour grid showing attack density by day and hour (UTC).
**Source:** Two-level date histogram: day × hour.

### Botnet Fingerprints
Auto-detected campaigns from credential and command clustering. Each card has All/7d/24h timeline selectors. Click a card to open AI Analysis modal.
**Source:** Live OpenSearch queries — no hardcoded signatures. Campaigns detected when 3+ IPs share the same credential pair or command signature.
**Confidence scoring:** HIGH = 5+ IPs, MEDIUM = 3–4, LOW = 1–2.

### Top Credentials Attempted
Table of username/password pairs ranked by attempt count. Click to copy to clipboard. COMPROMISED badge if success rate = 100%.
**Source:** Painless script aggregation joining username + password fields.

### Credential Intelligence
Summary stats (failed/success/unique/rate) plus table with per-credential success rates.
**Source:** Separate enriched stats query counting `cowrie.login.success` vs total.

### Top Commands Executed
Commands run by attackers after gaining access. High counts = automated botnet.
**Source:** `data.command` from `cowrie.command.input` events.

### Attacker Intelligence
Top 5 attackers by threat level (default), expandable to all. Each row shows SSH KEY / DOWNLOAD / LOGIN badges. Expand for MITRE tactics with evidence, credentials tried, threat indicators with proof commands.
**Source:** Session data from `/api/sessions`, processed into per-IP aggregations client-side.

### MITRE ATT&CK Framework
All tactics found in your data, dynamically discovered from live OpenSearch aggregations. New tactics appear automatically when new Wazuh rules fire. Hover any tactic pill for the official ATT&CK definition. Hover technique IDs (T1110, T1098.004, etc.) for technique-level definitions. Click to expand real examples.
**Source:** `rule.mitre.tactic` and `rule.mitre.id` aggregations.

### On-Demand AI Analysis
Runs llama3.1:8b (Ollama on RTX 4070 via Tailscale). Three modes: Summary (~30s), Full (~3min), Executive (~5min). Results cached in triage_report.json.

---

## Status Bar (bottom)
Fixed bar showing:
- OpenSearch connectivity (green/yellow/red dot)
- GeoIP cache size (IPs resolved)
- Last refresh timestamp (updates every 10s)
- Alert count in current window

---

## What's NOT in the dashboard (yet)

| Honeypot | Status | What it would add |
|----------|--------|-------------------|
| Dionaea | Running on VPS, not synced | Malware binaries captured, exploit attempts (SMB, FTP, MSSQL, MySQL, HTTP), binary hashes |
| nginx HTTP | Running on VPS, not synced | HTTP scanning, web exploit attempts, CVE probes, path traversal |

Adding these requires: sync Dionaea's sqlite/json logs to Ubuntu Server, write Wazuh decoders for each format, add new panels to the dashboard.
