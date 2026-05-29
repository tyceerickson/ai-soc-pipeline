# AI-Powered SOC Pipeline

**CMU MSISPM Portfolio — Project 4**  
Tyce Erickson · May 2026

A production-grade, AI-powered Security Operations Center pipeline built on real internet attack data. Three honeypots exposed to the public internet collect live attack traffic across SSH, web, and malware-capture vectors. Data is processed through a Wazuh SIEM, enriched with geolocation intelligence, and analyzed by a locally-hosted large language model. A custom real-time dashboard provides 11 integrated threat intelligence panels across three honeypot sources.

> **This is not a simulation. Every alert in this dataset came from a real attacker.**

---

## Live Stats (as of May 29, 2026)

| Metric | Value |
|--------|-------|
| Total Wazuh alerts | 6,185,397+ |
| Cowrie SSH events | 872,871 |
| nginx web requests | 1,352+ |
| Unique attacker IPs | 1,000+ |
| Countries observed | 99 |
| Active botnets identified | 6 |
| MITRE ATT&CK tactics | 7 |
| Collection period | May 21 – 29, 2026 |

---

## Architecture

```
Internet Attackers
        │
        ▼
[DigitalOcean VPS — NYC1]          [Alienware m16 R2]
  Cowrie SSH/Telnet Honeypot         Ollama + llama3.1:8b
  nginx Web Honeypot                 RTX 4070 (8GB VRAM)
  Dionaea Malware Capture
        │                                   │
        │  rsync / 15min (Tailscale)        │ HTTP API (Tailscale)
        ▼                                   │
[Ubuntu Server — aarch64]                   │
  Wazuh SIEM + OpenSearch                   │
  GeoIP Enrichment Pipeline                 │
  parse_nginx.py + parse_dionaea.py         │
  Flask SOC Dashboard ──────────────────────┘
        │
        ▼
  Browser (Tailscale only)
  http://100.82.166.75:5000
```

Three machines connected via Tailscale mesh VPN. The dashboard is not accessible from the public internet.

---

## Dashboard

The custom Flask dashboard provides 11 real-time intelligence panels across two sections:

### Cowrie SSH Honeypot
| Panel | Description |
|-------|-------------|
| Alert Timeline | Time series with severity and MITRE ATT&CK overlay |
| Geographic Attack Map | Natural Earth world map with volume-scaled attack dots |
| Attack Chain Funnel | Kill chain dropout rates: Connect → KEX → Login → Commands → Downloads |
| Attack Velocity | Real-time attacks/min with 60-min spark chart |
| Attack Heatmap | 14-day hour×day intensity grid |
| Botnet Fingerprints | Auto-detected campaigns with timelines and AI analysis on-click |
| Credential Intelligence | Success rates, coordinated attack detection, botnet badges |
| Attacker Intelligence | Threat-scored attackers with full session breakdown |
| MITRE ATT&CK Framework | Dynamic tactic/technique mapping from live alert data |
| On-Demand AI Analysis | llama3.1:8b summary, full, and executive triage modes |

### Multi-Honeypot Intelligence (nginx + Dionaea)
| Panel | Description |
|-------|-------------|
| Dionaea Malware Capture | Service breakdown, top IPs, malware binary hashes, activity timeline |
| nginx Web Honeypot | Scanner fingerprints, CVE probe paths, user agents, request timeline |
| Cross-Honeypot Attackers | IPs seen attacking both Dionaea and nginx simultaneously |

---

## Key Findings

### The mdrfckr Botnet
The most sophisticated campaign observed. Installs a persistent SSH backdoor via `~/.ssh/authorized_keys` using a distinctive RSA key ending in `mdrfckr`. Uses `chattr -ia` (immutable flag) to prevent key removal even by root. 90,529 implant attempts in 7 days from hundreds of IPs routing through Pfcloud UG VPN nodes.

### The 345gs5662d34 Campaign
Massive credential stuffing using `root/3245gs5662d34` — attempted 103,084 times from 357 unique IPs. A coordinated multi-source campaign representing the largest single-credential effort in the dataset.

### nginx Web Honeypot Findings
Within 7 days of deployment: 1,292 requests from 115 unique IPs probing 940 unique paths. Active threats include IoT botnets (481 hits), `.env` credential theft targeting SendGrid/Twilio API keys, Hikvision CVE-2021-36260 RCE probes, TP-Link router firmware exploits (CVE-2021-22161), and Tomcat manager panel brute-force.

### Attack Scale
At peak (May 23, 2026): 2,019,221 alerts in a single day — driven by two overlapping botnet campaigns. The average daily background rate is ~67,000 alerts — roughly one attack event every 1.3 seconds.

---

## Repository Structure

```
ai-soc-pipeline/
├── dashboard/
│   ├── app.py                    # Flask backend — 14 API endpoints
│   └── templates/
│       └── index.html            # SOC dashboard frontend
├── pipeline/
│   ├── parse_dionaea.py          # Dionaea SQLite → Wazuh JSON parser
│   └── parse_nginx.py            # nginx CLF → Wazuh JSON parser
├── triage/
│   ├── ai_triage.py              # LLM threat analysis engine
│   ├── alert_poller.py           # OpenSearch alert sampler
│   └── triage_runner.py          # 30-min cron orchestrator
├── config/
│   ├── soc-dashboard.service     # Systemd service unit
│   ├── geoip-enrich.cron         # Hourly enrichment cron
│   ├── wazuh-cowrie-rules.xml    # Cowrie detection rules (IDs 100100-100110)
│   ├── wazuh-honeypot-web-rules.xml  # Dionaea + nginx rules (IDs 100200-100360)
│   └── wazuh-ossec-snippet.xml   # Wazuh agent localfile config
├── docs/
│   ├── 01-architecture.md        # System design and data flow
│   ├── 02-wazuh-installation.md  # SIEM deployment guide
│   ├── 03-log-ingestion-setup.md # Pipeline documentation
│   ├── 04-custom-rules.md        # Wazuh rules and MITRE mapping
│   ├── 05-ai-triage-design.md    # AI system design
│   ├── 06-dashboard-guide.md     # Panel reference guide
│   ├── 07-alert-samples.md       # Real attack analysis
│   ├── 08-lessons-learned.md     # Technical retrospective
│   └── 09-executive-summary.md   # CISO-level summary
├── data/samples/                 # Sample alert JSON for testing
├── requirements.txt
└── README.md
```

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats?minutes=N` | Full stats: timeline, countries, IPs, MITRE, credentials, commands |
| `GET /api/attack_chain?minutes=N` | Kill chain funnel stage counts |
| `GET /api/velocity` | Real-time attacks/min + 60-min spark data |
| `GET /api/heatmap` | 14-day hour×day attack matrix |
| `GET /api/sessions?minutes=N` | Top sessions with full event chains |
| `GET /api/botnets?minutes=N` | Behavioral botnet fingerprints |
| `GET /api/intel?minutes=N` | Parallel: attack chain + sessions + botnets + cred_intel |
| `GET /api/cred_intel?minutes=N` | Credential success rates + coordination detection |
| `POST /api/botnet_analysis` | AI analysis of a specific campaign |
| `GET /api/dionaea?minutes=N` | Dionaea malware honeypot stats |
| `GET /api/nginx?minutes=N` | nginx web honeypot stats |
| `GET /api/honeypots?minutes=N` | Combined Dionaea + nginx (parallel) |
| `GET /api/triage` | Latest AI triage report |
| `POST /api/analysis/run` | Trigger on-demand AI analysis |

---

## Technology Stack

- **Honeypots:** Cowrie SSH/Telnet, nginx, Dionaea (Docker on DigitalOcean NYC1)
- **Transport:** rsync over Tailscale VPN (15-min intervals)
- **Enrichment:** Python + MaxMind GeoLite2 (City + ASN databases)
- **Log Parsers:** Custom Python parsers for nginx CLF and Dionaea SQLite formats
- **SIEM:** Wazuh 4.x + OpenSearch (Ubuntu Server, aarch64)
- **Backend:** Python 3, Flask, urllib (zero external HTTP dependencies)
- **Frontend:** Vanilla HTML/CSS/JS, HTML5 Canvas, Natural Earth 50m geodata
- **AI:** Ollama + llama3.1:8b on NVIDIA RTX 4070 (fully local inference)
- **Network:** Tailscale mesh VPN (zero-trust overlay, no public dashboard exposure)

---

## Setup

See `docs/02-wazuh-installation.md` for full deployment instructions. High-level steps:

1. Deploy Cowrie, nginx, and Dionaea on a VPS (Docker Compose)
2. Install Wazuh all-in-one on your SIEM server
3. Configure rsync from VPS → SIEM server via Tailscale
4. Deploy log parsers (`pipeline/`) as 15-min cron jobs
5. Set up GeoIP enrichment cron (`config/geoip-enrich.cron`)
6. Add Wazuh rules (`config/wazuh-cowrie-rules.xml`, `config/wazuh-honeypot-web-rules.xml`)
7. Deploy the Flask dashboard (`config/soc-dashboard.service`)
8. Install Ollama and pull llama3.1:8b on your AI inference machine

---

## Documentation

Full project documentation is in the `docs/` directory:

- **Architecture** — System design, data flow, infrastructure details
- **Wazuh Installation** — SIEM deployment and configuration
- **Log Ingestion** — Pipeline from honeypot to SIEM
- **Custom Rules** — Wazuh decoders, rules, MITRE mapping
- **AI Triage Design** — LLM integration and prompt engineering
- **Dashboard Guide** — Panel reference and interpretation
- **Alert Samples** — Real attack session analysis
- **Lessons Learned** — Technical retrospective
- **Executive Summary** — CISO-level findings and significance

---

Built as Project 4 of 4 for CMU MSISPM application portfolio. All data collected from real internet attack traffic on infrastructure owned and operated by the author.
