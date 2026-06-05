# 06 — Dashboard Guide

## Overview

The SOC dashboard is a custom Flask web application (`app.py`) providing real-time visibility into all three honeypots. It queries OpenSearch (Wazuh) directly for live statistics, renders 12 intelligence panels across three sections, and integrates with Ollama `llama3.1:8b` for on-demand threat analysis. Accessible at `http://100.82.166.75:5000` via Tailscale.

**Data sources:** the dashboard visualizes **all three honeypots** — Cowrie (SSH/Telnet), Dionaea (malware capture), and nginx (web). The Cowrie panels cover the highest-volume SSH attack data; the Multi-Honeypot section covers malware capture and web scanning; the Threat Actor Correlation panel unifies activity across all three.

---

## Alert Source Explained

### Where alerts come from
Every number comes from **Wazuh OpenSearch** (`wazuh-alerts-4.x-*`). Wazuh receives the normalized `{"data":{...}}`-wrapped JSON feeds produced by the parsers/forwarders on the Ubuntu Server (pulled from the VPS by per-honeypot systemd timers — cowrie/nginx every 5 min, dionaea every 15 min). Flow:
```
VPS honeypots → sync timers (rsync) → Ubuntu Server parsers/forwarder → Wazuh → OpenSearch → Dashboard
```

### What is a "Wazuh alert"?
A Wazuh alert is a **rule-violation event** generated when a log line matches a rule. One honeypot event can generate multiple alerts if it matches multiple rules, so raw alert counts are always higher than raw event/session counts. All dashboard queries filter `{"exists": {"field": "data.honeypot"}}`.

### Credentials are read from the environment
The dashboard authenticates to OpenSearch using the `OPENSEARCH_PASS` environment variable (set in `soc-dashboard.service`). No credentials are stored in source.

### Top Attacker Countries and the Geographic Map
Both the Countries bar chart and the Geographic Map now derive from the **same source**: the GeoIP-enriched top-IP list (`geoip_cache.json`). This was a deliberate fix — Cowrie events lack a `data.location.country_name` field, so the old country aggregation on that field returned nothing for the highest-volume honeypot. Deriving both panels from the GeoIP-resolved IP list keeps them consistent across all three honeypots.

---

## Panel Reference

### Cowrie SSH Honeypot

**Live Alert Summary** — Total / Critical (L15) / High (L12–14) / Medium (L7–11) / Low (L0–6), from a `rule.level` aggregation.

**Alert Timeline** — Canvas time series; click a spike for the Spike Detail Modal (MITRE tactics, countries, campaigns, top IPs in that bucket). Bucket sizes scale with the window (5m ≤2h … 6h for 7d).

**Geographic Attack Map** — Natural Earth world map with attack dots sized by volume; uses GeoIP-resolved IPs.

**Top Attacker IPs / Countries** — `data.src_ip` and `data.location.country_name` aggregations, GeoIP-enriched.

**Attack Velocity** — Live 60-minute attacks/min spark chart; polls every 30s.

**Attack Chain Funnel** — Kill-chain progression: Connect → KEX → Login → Commands → Downloads → Uploads, from per-eventid counts.

**Attack Heatmap** — 14-day × 24-hour density grid (UTC), two-level date histogram.

**Botnet Fingerprints** — Auto-detected campaigns from credential/command clustering (no hardcoded signatures); detected when 3+ IPs share a credential pair or command signature. Confidence: HIGH ≥5 IPs, MEDIUM 3–4, LOW 1–2. Each card has All/7d/24h selectors and an on-click AI Analysis modal.

**Credential Intelligence** — Failed/success/unique counts and per-credential success rate (`success / (success + failed)`). Distinctive botnet usernames (e.g. `mdrfckr`) are surfaced as named campaigns.

**Attacker Intelligence** — Top attackers driven by the cross-honeypot `/api/threat_actors` aggregation (every source IP across SSH/web/malware, not a Cowrie-session sample — which previously collapsed the panel to a single IP on long windows). Each row shows attack-vector badges (SSH / WEB / MALWARE), a multi-vector badge, and SSH-KEY / MALWARE / BREACH / CVE indicators, ranked by a composite threat score. Expand for MITRE tactics, credentials tried, top commands, and threat indicators; a 🔍 button opens the full per-IP attack narrative.

**MITRE ATT&CK Framework** — Tactics/techniques discovered dynamically from `rule.mitre.*` aggregations; hover for definitions, click to expand examples.

**On-Demand AI Analysis** — `llama3.1:8b` (Ollama via Tailscale). Summary (~30s), Full (~3min), Executive (~5min). Results cached in `triage_report.json`.

### Multi-Honeypot Intelligence (nginx + Dionaea)

The activity box supports **1h / 1d / 7d / 30d** windows and tab persistence with per-tab count badges.

**Dionaea Malware Capture** — Service breakdown (SMB/FTP/MSSQL/MySQL), top source IPs, and the captured-malware list. Each binary card shows the **VirusTotal verdict** (e.g. 66/76 flagged), **malware family** (e.g. `trojan.wannacry/wanna`), source IP + country, service, file size, capture count, and a link to the VT report. Click the SHA256 to copy it. (Captured binaries are computed to real SHA256 from the file on disk; see `03-log-ingestion-setup.md`.)

**nginx Web Honeypot** — Scanner fingerprints, CVE probe paths (Hikvision, TP-Link, Tomcat, Log4Shell), `.env` credential-theft attempts, user agents, and request timeline.

**Cross-Honeypot Attackers** — IPs observed attacking more than one honeypot, with per-honeypot counts.

### Threat Actor Correlation

**Threat Actor Correlation** — The flagship correlation view. Each row is **one source IP**, with its activity unified across all three honeypots into a single threat-scored profile. Actors are ranked by a composite score (attack-vector breadth, rule severity, malware delivery, confirmed SSH breach, persistence). Multi-vector actors — e.g. an IP that brute-forces SSH *and* delivers malware over SMB — are badged and float to the top, revealing coordinated actors that siloed per-sensor panels would miss. Clicking a row opens the full **attack-narrative drawer**: a plain-language story, an ordered kill-chain strip (recon → access → execution → download → persistence), credentials tried with the successful pair highlighted, captured malware with VirusTotal verdicts, web/CVE probes, detected persistence mechanisms, a **per-tactic "why this command maps here" evidence breakdown**, and a copyable IOC block — served by `GET /api/actor/<ip>`. A companion **Most Dangerous Attackers** panel ranks the top actors by a destruction-weighted score (malware delivery, breach, persistence) with the same lazy-loaded deep-dive.

### Incident Management

**Alert Drawer** — `GET /api/alert/<ip>` opens a full context panel for any source IP (recent events, geo, credentials, commands; copy-as-JSON), enriched with the cross-honeypot attack narrative from `GET /api/actor/<ip>` (kill-chain phases, per-tactic command evidence, malware/VT, persistence, copyable IOCs).

**Search / Pivot** — `GET /api/search?q=&type=ip|cred|cmd` pivots across IPs, credentials, and commands.

**Cases** — Create/track incident cases (status open/investigating/closed, severity, notes, linked alerts, audit log) backed by a local SQLite store (`schema.sql`); CSV export supported.

**Response Playbooks** — Five built-in playbooks for common honeypot findings.

---

## Status Bar
OpenSearch connectivity (green/yellow/red), GeoIP cache size, honeypot health, last-refresh timestamp (updates every 10s), and alert count in the current window.

---

## Notes on Copy-to-Clipboard
The dashboard is served over plain HTTP on the Tailscale network, where the browser's secure-context `navigator.clipboard` API is unavailable. A fallback copy helper (using `execCommand`) is used so SHA256 hashes, credentials, and alert JSON can be copied regardless.
