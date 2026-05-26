# 05 — AI Triage System Design

## Overview

The AI triage system takes raw OpenSearch alert data, pre-aggregates it into structured threat intelligence, and sends a carefully engineered prompt to a locally-hosted large language model (LLM) running on an NVIDIA RTX 4070. The model produces natural-language threat assessments, attacker profiles, IOC lists, and — in executive mode — a CISO-ready summary with recommended actions.

The system runs automatically every 30 minutes in summary mode and can be triggered on-demand from the dashboard in three modes: Summary, Full, and Executive.

---

## Architecture

```
OpenSearch (wazuh-alerts-4.x-*)
         │
         │  alert_poller.py
         │  (filters, samples, deduplicates)
         ▼
  alerts_raw.json (structured alert sample)
         │
         │  ai_triage.py
         │  (pre-aggregation + prompt engineering)
         ▼
  Prompt → Ollama HTTP API (Tailscale)
         │
         │  llama3.1:8b on RTX 4070
         │  (15-30 sec inference)
         ▼
  triage_report.json
         │
         ▼
  Dashboard /api/triage
```

---

## Component 1: Alert Poller (`alert_poller.py`)

The poller queries OpenSearch for recent honeypot alerts, filters by minimum severity level, deduplicates by rule ID, and writes a structured sample to `alerts_raw.json`.

### Key Parameters
- `--minutes` — lookback window (default: 60)
- `--min-level` — minimum Wazuh rule level (default: 6)
- `--limit` — maximum alerts to sample (default: 100)
- `--honeypot-only` — restricts to `data.honeypot` field (always set)

### Output Structure (`alerts_raw.json`)
```json
{
  "stats": {
    "total_alerts": 45230,
    "window_minutes": 1440,
    "top_countries": {"Indonesia": 12450, "United States": 8230},
    "top_ips": [{"ip": "103.133.160.33", "count": 748369}],
    "severity_breakdown": {"critical": 0, "high": 13801, "medium": 563404}
  },
  "alerts": [
    {
      "rule_id": "100108",
      "level": 15,
      "description": "SSH authorized_keys implant detected",
      "src_ip": "45.156.87.254",
      "country": "Bulgaria",
      "username": "root",
      "password": "3245gs5662d34",
      "command": "cd ~ && rm -rf .ssh && mkdir .ssh && echo 'ssh-rsa AAAAB3...mdrfckr'",
      "count": 1
    }
  ]
}
```

---

## Component 2: AI Triage (`ai_triage.py`)

### Intelligence Pre-Aggregation

Before sending to the LLM, `ai_triage.py` queries OpenSearch directly for full-dataset statistics. This ensures the AI receives accurate counts across the entire time window, not just the sampled alerts:

- Total alert count by severity
- Top 20 attacker countries with event counts
- Top 20 source IPs with event counts and GeoIP data
- Top credential pairs with attempt counts
- Top executed commands with counts
- Active MITRE tactics and their event counts
- Botnet detection based on credential/command signatures

This pre-aggregation step is critical — without it, the LLM would only see 100 sampled alerts and would under-report the true scale of the attack activity.

### Prompt Engineering

The system uses structured prompts with explicit JSON output requirements. Example (summary mode):

```
You are a senior SOC analyst reviewing honeypot threat intelligence.
Analyze this attack data and provide a structured threat assessment.

ATTACK STATISTICS (last 1440 minutes):
- Total alerts: 6,185,397
- Critical: 0 | High: 13,801 | Medium: 563,404 | Low: 5,608,192
- Unique source IPs: 944 across 99 countries
- Top attackers: Indonesia (897,195), United States (758,634), ...
- Top credentials: root/3245gs5662d34 (103,084×), 345gs5662d34/345gs5662d34 (102,804×)
- Top commands: cd ~; chattr -ia .ssh; lockr -ia .ssh (90,529×)
- Active botnets: mdrfckr SSH key implant, 345gs5662d34 credential campaign

TOP ALERTS (sampled, highest severity first):
[... alert details ...]

Respond ONLY with valid JSON matching this schema:
{
  "severity_verdict": "critical|high|medium|low",
  "threat_assessment": "...",
  "attacker_profile": "...",
  "mitre_summary": "...",
  "iocs": {
    "ip_addresses": [...],
    "credentials": [...],
    "commands": [...]
  },
  "analyst_notes": "..."
}
```

### Analysis Modes

| Mode | Description | Typical Runtime |
|------|-------------|-----------------|
| Summary | Top 10 alerts, single LLM call | 15-30 seconds |
| Full | All alerts in batches of 25, multiple LLM calls | 2-4 minutes |
| Executive | Full analysis + CISO summary with key findings and recommendations | 4-6 minutes |

### Model Selection

**`llama3.1:8b`** was chosen after testing:
- `llama3.3:70b` — excellent reasoning but 42GB RAM required offloading from VRAM to system RAM, causing 10+ minute inference times. Rejected.
- `llama3.1:8b` — fits entirely in the RTX 4070's 8GB VRAM. 15-30 second inference per call. Produces coherent, structured JSON with good threat reasoning. Selected.

---

## Component 3: Triage Runner (`triage_runner.py`)

A cron-driven orchestrator that runs the full pipeline automatically:

```bash
# Cron entry (Ubuntu Server user crontab)
*/30 * * * * /usr/bin/python3 /opt/wazuh-soc/triage/triage_runner.py --mode summary --minutes 60
```

The runner:
1. Runs `alert_poller.py` to fetch current alerts
2. Runs `ai_triage.py` with the specified mode and window
3. Writes output to `triage_report.json`
4. The dashboard reads this file on the `/api/triage` endpoint

### Output (`triage_report.json`)
```json
{
  "generated_at": "2026-05-26T10:30:00Z",
  "model": "llama3.1:8b",
  "mode": "summary",
  "alerts_analyzed": 100,
  "window_minutes": 60,
  "triage_results": [
    {
      "severity_verdict": "high",
      "threat_assessment": "The honeypot is experiencing active credential stuffing...",
      "attacker_profile": "Multiple coordinated botnets targeting SSH...",
      "mitre_summary": "Primary tactics: Discovery (T1046), Credential Access (T1110)...",
      "iocs": {
        "ip_addresses": ["103.133.160.33", "192.109.200.78"],
        "credentials": ["root/3245gs5662d34", "345gs5662d34/345gs5662d34"],
        "commands": ["cd ~ && rm -rf .ssh && mkdir .ssh && echo 'ssh-rsa...'"]
      },
      "analyst_notes": "The mdrfckr SSH key implant campaign is the most significant..."
    }
  ]
}
```

---

## Botnet-Specific Analysis

The dashboard supports on-demand AI analysis for individual botnets. Clicking "AI Analysis" on any botnet card in the Botnet Fingerprints panel sends a POST to `/api/botnet_analysis` with the botnet name, event count, and unique IP count.

The backend fetches 5 sample events from that botnet using signature-based queries, then sends a targeted prompt to the LLM asking for:
- **Description:** What is this botnet and what is its goal?
- **Methodology:** How does it operate — credentials, commands, attack pattern?
- **Detection:** How was it recognized in this honeypot?
- **Threat Assessment:** What could it do on a real system?

Results are cached per session so each botnet is only analyzed once per browser session.

---

## Ollama Setup (Alienware)

Ollama runs as a Windows service on the Alienware, bound to the Tailscale interface:

```powershell
# Install Ollama
winget install Ollama.Ollama

# Pull the model
ollama pull llama3.1:8b

# Configure to listen on Tailscale IP
# Set environment variable: OLLAMA_HOST=100.72.171.104:11434
# Restart the Ollama service
```

The Ubuntu Server reaches Ollama at `http://100.72.171.104:11434` via Tailscale. No ports are exposed to the public internet.
