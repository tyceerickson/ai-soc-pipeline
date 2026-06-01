# 05 — AI Triage System Design

## Overview

The AI triage system takes raw OpenSearch alert data, pre-aggregates it into structured threat intelligence, and sends a carefully engineered prompt to a locally-hosted large language model (LLM) running on an NVIDIA RTX 4070. The model produces natural-language threat assessments, attacker profiles, IOC lists, and — in executive mode — a CISO-ready summary with recommended actions.

The system runs automatically every 30 minutes in summary mode and can be triggered on-demand from the dashboard in three modes: Summary, Full, and Executive.

---

## Architecture

```
OpenSearch (wazuh-alerts-4.x-*)
         │  alert_poller.py  (filters, samples, deduplicates)
         ▼
  alerts_raw.json (structured alert sample)
         │  ai_triage.py  (pre-aggregation + prompt engineering)
         ▼
  Prompt → Ollama HTTP API (Tailscale) → llama3.1:8b on RTX 4070 (15–30s)
         ▼
  triage_report.json → Dashboard /api/triage
```

---

## Component 1: Alert Poller (`alert_poller.py`)

Queries OpenSearch for recent honeypot alerts, filters by minimum severity, deduplicates by rule ID, and writes a structured sample to `alerts_raw.json`. Reads the OpenSearch password from the `OPENSEARCH_PASS` environment variable (no hardcoded credentials).

### Key Parameters
- `--minutes` — lookback window (default: 60)
- `--min-level` — minimum Wazuh rule level (default: 6)
- `--limit` — maximum alerts to sample (default: 100)
- `--honeypot-only` — restrict to `data.honeypot` (always set)

### Output (`alerts_raw.json`)
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
      "rule_id": "100108", "level": 15,
      "description": "SSH authorized_keys implant detected",
      "src_ip": "45.156.87.254", "country": "Bulgaria",
      "username": "root", "password": "345gs5662d34",
      "command": "cd ~ && rm -rf .ssh && mkdir .ssh && echo 'ssh-rsa AAAAB3...mdrfckr'"
    }
  ]
}
```

---

## Component 2: AI Triage (`ai_triage.py`)

### Intelligence Pre-Aggregation
Before prompting the LLM, `ai_triage.py` queries OpenSearch directly for full-dataset statistics so the model sees accurate counts across the whole window, not just the 100 sampled alerts:

- Total alerts by severity
- Top 20 countries and top 20 source IPs (with GeoIP)
- Top credential pairs and top executed commands (with counts)
- Active MITRE tactics
- Botnet detection from credential/command signatures
- **Captured malware** (count, hashes, VirusTotal verdicts) from `dionaea.binary.captured` events

Without this step the LLM would under-report the true scale.

### Prompt Engineering (summary mode example)
```
You are a senior SOC analyst reviewing honeypot threat intelligence.

ATTACK STATISTICS (last 1440 minutes):
- Total alerts: 11,611,908
- Unique source IPs: 1,000+ across 99 countries
- Top credentials: root/345gs5662d34 (103,084×), 345gs5662d34/345gs5662d34 (102,804×)
- Top command: cd ~; chattr -ia .ssh; lockr -ia .ssh (90,529×)
- Active botnets: mdrfckr SSH key implant, 345gs5662d34 credential campaign
- Malware captured: 7 binaries (6 WannaCry, 1 downloader), VirusTotal-verified

Respond ONLY with valid JSON:
{ "severity_verdict": "...", "threat_assessment": "...", "attacker_profile": "...",
  "mitre_summary": "...", "iocs": {"ip_addresses":[...],"credentials":[...],"commands":[...]},
  "analyst_notes": "..." }
```

### Analysis Modes
| Mode | Description | Typical Runtime |
|------|-------------|-----------------|
| Summary | Top 10 alerts, single LLM call | 15–30s |
| Full | All alerts in batches of 25 | 2–4 min |
| Executive | Full analysis + CISO summary with recommendations | 4–6 min |

### Model Selection
- `llama3.3:70b` — excellent reasoning, but ~42GB forced VRAM→RAM offload and 10+ min inference. Rejected.
- `llama3.1:8b` — fits entirely in the RTX 4070's 8GB VRAM, 15–30s per call, coherent structured JSON. Selected.

---

## Component 3: Triage Runner (`triage_runner.py`)

Cron-driven orchestrator (reads `OPENSEARCH_PASS` from the user crontab environment):
```cron
OPENSEARCH_PASS=<set-in-crontab-env>
*/30 * * * * /usr/bin/python3 /opt/wazuh-soc/triage/triage_runner.py --mode summary --minutes 60
```
It runs `alert_poller.py`, then `ai_triage.py`, writes `triage_report.json`, and the dashboard serves it at `/api/triage`.

---

## Botnet-Specific Analysis

Clicking "AI Analysis" on any botnet card POSTs to `/api/botnet_analysis` with the campaign name and counts. The backend pulls sample events via signature-based queries and prompts the LLM for description, methodology, detection basis, and threat assessment. Results are cached per browser session.

---

## Ollama Setup (Alienware)

```powershell
winget install Ollama.Ollama
ollama pull llama3.1:8b
# Bind to Tailscale: set OLLAMA_HOST=100.72.171.104:11434, restart the service
```

The Ubuntu Server reaches Ollama at `http://100.72.171.104:11434` via Tailscale. No ports are exposed to the public internet.
