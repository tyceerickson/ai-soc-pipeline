# AI-Powered SOC Pipeline

**CMU MSISPM Portfolio — Project 4**  
*Tyce Erickson · May 2026*

A production-grade, AI-powered Security Operations Center pipeline built on real internet attack data. An SSH honeypot exposed to the public internet collects live attack traffic, which is processed through a Wazuh SIEM, enriched with geolocation intelligence, and analyzed by a locally-hosted large language model. A custom real-time dashboard provides 8 integrated threat intelligence panels.

**This is not a simulation. Every alert in this dataset came from a real attacker.**

---

## Live Stats (as of May 26, 2026)

| Metric | Value |
|--------|-------|
| Total Wazuh alerts | **6,185,397** |
| Cowrie SSH events | **218,392** |
| Unique attacker IPs | **944** |
| Countries observed | **99** |
| Active botnets identified | **6** |
| MITRE ATT&CK tactics | **7** |
| Collection period | May 19 – 26, 2026 |

---

## Architecture

```
Internet Attackers
       │
       ▼
[DigitalOcean VPS — NYC1]       [Alienware m16 R2]
 Cowrie SSH Honeypot             Ollama + llama3.1:8b
 Nginx · Dionaea                 RTX 4070 (8GB VRAM)
       │                               │
       │  rsync / 15min (Tailscale)    │  HTTP API (Tailscale)
       ▼                               │
[Ubuntu Server — aarch64]              │
 Wazuh SIEM + OpenSearch               │
 GeoIP Enrichment Pipeline             │
 Flask SOC Dashboard ──────────────────┘
       │
       ▼
 Browser (Tailscale only)
 http://100.82.166.75:5000
```

Three machines connected via Tailscale mesh VPN. The dashboard is not accessible from the public internet.

---

## Dashboard

The custom Flask dashboard provides 8 real-time intelligence panels:

| Panel | Description |
|-------|-------------|
| **Alert Timeline** | Time series with severity and MITRE ATT&CK overlay |
| **Geographic Attack Map** | Natural Earth world map with volume-scaled attack dots |
| **Attack Chain Funnel** | Kill chain dropout rates: Connect → KEX → Login → Commands → Downloads |
| **Attack Velocity** | Real-time attacks/min with 30-minute spark chart |
| **Attack Heatmap** | 14-day hour×day intensity grid |
| **Botnet Fingerprints** | 6 detected campaigns with timelines and AI analysis on-click |
| **Credential Intelligence** | Success rates, coordinated attack detection, botnet badges |
| **Session Depth Analyzer** | Complete kill chain per session, expandable event timeline |

Plus: Top Attacker Countries, Top Attacker IPs, Event Types, Top Credentials, Top Commands, MITRE ATT&CK Framework, On-Demand AI Analysis.

---

## Key Findings

### The mdrfckr Botnet
The most sophisticated campaign observed. Installs a persistent SSH backdoor via `~/.ssh/authorized_keys` using a distinctive RSA key ending in `mdrfckr`. Uses `chattr -ia` (immutable flag) to prevent key removal even by root. **90,529 implant attempts in 7 days** from hundreds of IPs routing through Pfcloud UG VPN nodes.

### The 345gs5662d34 Campaign
Massive credential stuffing using `root/3245gs5662d34` — attempted **103,084 times** from 357 unique IPs. A coordinated multi-source campaign representing the largest single-credential effort in the dataset.

### Attack Scale
At peak (May 23, 2026): **2,019,221 alerts in a single day** — driven by two overlapping botnet campaigns reaching simultaneous peak activity. The average daily background rate is ~67,000 alerts — roughly one attack event every 1.3 seconds.

---

## Repository Structure

```
ai-soc-pipeline/
├── dashboard/
│   ├── app.py                   # Flask backend (v3) — 8 API endpoints
│   └── templates/
│       └── index.html           # SOC dashboard frontend
├── triage/
│   ├── ai_triage.py             # LLM threat analysis engine
│   ├── alert_poller.py          # OpenSearch alert sampler
│   └── triage_runner.py         # 30-min cron orchestrator
├── config/
│   ├── soc-dashboard.service    # Systemd service unit
│   ├── geoip-enrich.cron        # Hourly enrichment cron
│   ├── wazuh-cowrie-rules.xml   # Custom Wazuh detection rules
│   └── wazuh-ossec-snippet.xml  # Wazuh agent config
├── docs/
│   ├── 01-architecture.md       # System design and data flow
│   ├── 02-wazuh-installation.md # SIEM deployment guide
│   ├── 03-log-ingestion-setup.md # Pipeline documentation
│   ├── 04-custom-rules.md       # Wazuh rules and MITRE mapping
│   ├── 05-ai-triage-design.md   # AI system design
│   ├── 06-dashboard-guide.md    # Panel reference guide
│   ├── 07-alert-samples.md      # Real attack analysis
│   ├── 08-lessons-learned.md    # Technical retrospective
│   └── 09-executive-summary.md  # CISO-level summary
├── data/samples/                # Sample alert JSON for testing
├── requirements.txt
└── README.md
```

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats?minutes=N` | Full stats: timeline, countries, IPs, MITRE, credentials, commands |
| `GET /api/attack_chain?minutes=N` | Kill chain funnel stage counts |
| `GET /api/velocity` | Real-time attacks/min + 30-min spark data |
| `GET /api/heatmap` | 14-day hour×day attack matrix |
| `GET /api/sessions?minutes=N` | Top sessions with full event chains |
| `GET /api/botnets?minutes=N` | Behavioral botnet fingerprints |
| `GET /api/cred_intel?minutes=N` | Credential success rates + coordination detection |
| `POST /api/botnet_analysis` | AI analysis of a specific botnet |
| `GET /api/triage` | Latest AI triage report |
| `POST /api/analysis/run` | Trigger on-demand AI analysis |

---

## Technology Stack

- **Honeypot:** Cowrie SSH/Telnet, Nginx, Dionaea (Docker on DigitalOcean)
- **Transport:** rsync over Tailscale VPN (15-min intervals)
- **Enrichment:** Python + MaxMind GeoLite2 (City + ASN)
- **SIEM:** Wazuh 4.x + OpenSearch (Ubuntu Server, aarch64)
- **Backend:** Python 3, Flask, urllib (no external dependencies)
- **Frontend:** Vanilla HTML/CSS/JS, HTML5 Canvas, Natural Earth 50m geodata
- **AI:** Ollama + llama3.1:8b on NVIDIA RTX 4070 (local inference)
- **Network:** Tailscale mesh VPN (zero-trust overlay)

---

## Setup

See [docs/02-wazuh-installation.md](docs/02-wazuh-installation.md) for full deployment instructions. High-level steps:

1. Deploy Cowrie on a VPS (DigitalOcean, Vultr, Linode, etc.)
2. Install Wazuh all-in-one on your SIEM server
3. Configure rsync from VPS → SIEM server via Tailscale
4. Set up GeoIP enrichment cron (`config/geoip-enrich.cron`)
5. Deploy the Flask dashboard (`config/soc-dashboard.service`)
6. Install Ollama and pull `llama3.1:8b` on your AI inference machine
7. Configure Ollama to listen on Tailscale IP

---

## Documentation

Full project documentation is in the [`docs/`](docs/) directory:

- **[Architecture](docs/01-architecture.md)** — System design, data flow, infrastructure details
- **[Wazuh Installation](docs/02-wazuh-installation.md)** — SIEM deployment and configuration
- **[Log Ingestion](docs/03-log-ingestion-setup.md)** — Pipeline from honeypot to SIEM
- **[Custom Rules](docs/04-custom-rules.md)** — Wazuh decoders, rules, MITRE mapping
- **[AI Triage Design](docs/05-ai-triage-design.md)** — LLM integration and prompt engineering
- **[Dashboard Guide](docs/06-dashboard-guide.md)** — Panel reference and interpretation
- **[Alert Samples](docs/07-alert-samples.md)** — Real attack session analysis
- **[Lessons Learned](docs/08-lessons-learned.md)** — Technical retrospective
- **[Executive Summary](docs/09-executive-summary.md)** — CISO-level findings and significance

---

*Built as Project 4 of 4 for CMU MSISPM application portfolio. All data collected from real internet attack traffic on infrastructure owned and operated by the author.*
