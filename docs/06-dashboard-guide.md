# 06 — Dashboard Guide

## Overview

The SOC dashboard is a custom Flask web application that provides real-time visibility into honeypot attack data. It queries OpenSearch directly for live statistics, renders 8 intelligence panels, and integrates with the local LLM for on-demand threat analysis. The dashboard is accessible at `http://100.82.166.75:5000` via Tailscale.

---

## Access & Controls

### Time Window Selector
The dropdown in the top-right corner controls the analysis window for all panels:
- Last hour / 6 hours / 24 hours / 7 days / 30 days / 90 days

Changing the window reloads all panels simultaneously. The **Last 7 days** view is the recommended default for portfolio demonstrations — it shows the full attack dataset including the two major botnet waves.

### Refresh Data Button
Manually triggers GeoIP enrichment and Wazuh export for the latest logs. Useful if you want to ensure the most recent VPS data is reflected before running an AI analysis.

---

## Panel Reference

### Live Alert Summary (top row)
Five cards showing total alerts and breakdown by severity for the selected time window. Hover over **Critical**, **High**, **Medium**, or **Low** labels for a tooltip explaining what each severity level means, what Wazuh rule levels it corresponds to, and example events.

- **Critical (Level 15):** Active exploitation — SSH key implants, malware uploads
- **High (Level 12-14):** Successful logins, command execution, file downloads
- **Medium (Level 7-11):** Brute force attempts, known malicious credentials
- **Low (Level 0-6):** Session lifecycle events, connection establishment

---

### Alert Timeline
A canvas-based time series chart showing alert volume over the selected window. Controls:

- **Severity buttons** (Total/High/Medium/Low): Toggle individual severity series on/off
- **MITRE ATT&CK dropdown**: Overlay tactic-specific timelines on the same chart

The timeline clearly shows the two major attack waves: the May 22 peak (~1.3M alerts) and the larger May 23 peak (~2M alerts), both driven by botnet campaigns. The May 24-25 gap is visible as a flat line — this is the disk outage period where data was lost.

---

### Row 1: Top Attacker Countries + Geographic Attack Map

**Top Attacker Countries** shows a horizontal bar chart of the top 20 source countries. The sort order toggle (⇅) flips between descending (most attacks) and ascending. Indonesia consistently tops the chart due to the mdrfckr and 345gs5662d34 botnet infrastructure concentrated there.

**Geographic Attack Map** renders a world map using Natural Earth 50m geographic data with Douglas-Peucker simplification. Attack volume is represented by red dot size — larger dots indicate more attacks from that country. The blue-grey ocean and warm grey continents provide contrast against the dark dashboard theme. Hover over any dot to see country name and alert count.

---

### Row 2: Top Attacker IPs + Attack Velocity + Event Types

**Top Attacker IPs** lists individual IP addresses with their country and organization. The top attacker (103.133.160.33 — Universitas Mataram, Indonesia) had 748,369 alerts over 7 days, representing a single IP responsible for ~12% of all traffic. Sortable by IP, country, or alert count.

**Attack Velocity** shows the real-time attack rate in attacks per minute, calculated from the last 5 minutes. The spark bar chart shows per-minute activity for the last 30 minutes. Bars are colored red when the rate exceeds 2x the hourly average, yellow when above average. This panel refreshes every 30 seconds.

**Event Types** shows a breakdown of Cowrie event types as a bar chart. Key events:
- `session connect` / `session closed` — raw connection volume (~1.5M each)
- `login failed` / `login success` — authentication attempts (~413K / ~261K)
- `command input` — attacker commands executed (~285K)
- `session file_download` — files fetched from attacker servers (~105K)

---

### Row 3: Attack Chain Funnel + Attack Heatmap

**Attack Chain Funnel** visualizes the complete kill chain as a horizontal funnel showing how many attackers progressed through each stage. The right column shows the dropout rate from the previous stage:

| Stage | Count | Drop |
|-------|-------|------|
| Session Connect | 1,534,928 | baseline |
| SSH Key Exchange | 685,050 | 45% — many scanners don't complete KEX |
| Login Failed | 413,837 | 60% — after KEX, 60% attempt credentials |
| Login Success | 261,478 | 63% — Cowrie accepts all credentials |
| Command Executed | 285,926 | 109% — more commands than logins (multiple cmds/session) |
| File Downloaded | 105,310 | 37% — malware drop attempts |
| File Uploaded | 2,730 | 3% — rare bidirectional transfers |

Note: Commands exceeding 100% of logins is expected — a single session can execute many commands.

**Attack Heatmap** shows a 14-day heat map of attacks by hour and day (UTC). Each cell is one hour; color intensity from dark green (low) through orange to red (peak). Clicking any cell shows a banner with the exact count for that hour. The heatmap clearly shows:
- May 22-23: Intense red/orange cells during the botnet surge
- May 24: Orange, then blank (disk outage at 22:12 UTC)
- May 25: Resumes at 21:39 UTC, building back up

---

### Row 4: Botnet Fingerprints (full width)

Displays all detected botnets as individual cards in a responsive grid. Each card shows:
- Botnet name and color
- Total event count
- Unique IP count
- A spark chart showing activity over time (only the active period, skipping leading zeros)

**Click "🔍 AI Analysis"** on any card to trigger a real-time LLM analysis of that botnet. The modal shows:
- What the botnet is and its purpose
- How it operates (credentials, commands, attack pattern)
- How it was detected in this honeypot
- Threat level assessment

Results are cached per browser session — each botnet is only analyzed once.

**Detected Botnets:**
- **mdrfckr Botnet** — SSH key implant campaign using a distinctive RSA key ending in "mdrfckr". Installs persistent backdoor access by writing to `~/.ssh/authorized_keys` with `chattr -ia` to prevent removal.
- **345gs5662d34** — Massive credential stuffing campaign using `root/3245gs5662d34` and `345gs5662d34/345gs5662d34`. 103K+ attempts.
- **Solana Scanner** — Cryptocurrency-related scanner using `solana/solana`, `sol/sol`, `sol/123` credentials. Likely targeting Solana node infrastructure.
- **Admin Brute Force** — Generic admin credential sweeping (`admin/admin`, `admin/1234`, etc.)
- **Root Brute Force** — Root-focused dictionary attack
- **Telnet Scanner** — Telnet protocol connection attempts (IoT device targeting)

---

### Row 5: Top Credentials + Credential Intelligence

**Top Credentials Attempted** lists the 100 most-used username/password pairs with attempt counts. Sortable by credential or count. Credential pairs are extracted directly from OpenSearch aggregations using a Painless script to concatenate username/password fields.

**Credential Intelligence** provides deeper analysis:
- **Stats row:** Total failed attempts, total successes (Cowrie accepts all), unique credential pairs, overall success rate
- **Table:** Per-credential success rate, unique IP count, and coordination badge. Credentials used from 4+ unique IPs simultaneously are tagged "botnet"
- 63.3% success rate reflects Cowrie's design — it accepts all credentials as a honeypot

---

### Row 6: Top Commands + Session Depth Analyzer

**Top Commands Executed** shows the 100 most-executed commands with counts. Full commands are displayed with word-wrap for long payloads like SSH key implant strings.

**Session Depth Analyzer** shows the most interesting attack sessions — those with confirmed logins (`cowrie.login.success`), command execution, or file downloads. Each session card shows:
- Source IP, country, and organization
- Number of events in the session
- MITRE tactics observed
- Severity badge (MED/HIGH)

Expanding a session reveals the complete event timeline in chronological order with event type, timestamp, and payload (command or credentials). This is the kill chain made visible at the individual session level.

---

### Row 7: MITRE ATT&CK Framework

Displays all observed MITRE tactics as expandable rows. Each tactic shows:
- Technique IDs (e.g., T1046, T1110.001)
- Total event count and percentage of all MITRE-mapped events
- Up to 8 example alerts showing real attacker data

Seven tactics observed: Discovery, Credential Access, Persistence, Execution, Defense Evasion, Initial Access, Privilege Escalation.

---

### Row 8: On-Demand AI Analysis

Triggers the full AI triage pipeline on demand. Configuration:
- **Mode:** Summary (top 10 threats, ~30s) / Full (all alerts, ~3 min) / Executive (Full + CISO summary, ~5 min)
- **Timeframe:** 1 hour to 90 days
- **Alert Depth:** 10 to 500 top alerts sampled

The progress bar shows 4 steps: Enrich → Export → Poll → AI Analysis. Output includes threat verdict, threat assessment, attacker profile, MITRE summary, IOCs, analyst notes, and (in executive mode) key findings and recommended actions.

---

## Running the Dashboard

```bash
# The dashboard runs as a systemd service
sudo systemctl status soc-dashboard
sudo systemctl restart soc-dashboard

# View logs
journalctl -u soc-dashboard -f

# Manual start (for debugging)
cd /opt/wazuh-soc/dashboard
python3 app.py --host 0.0.0.0 --port 5000 --debug
```
