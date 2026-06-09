# Pipeline — Log Parsers & Malware Capture

This directory contains the Python parsers and sync automation that convert raw
honeypot data into Wazuh-compatible JSON for ingestion into OpenSearch.

## Files

| File | Purpose |
|------|---------|
| `parse_nginx.py` | Parses nginx Combined Log Format access logs into structured JSON events |
| `parse_dionaea.py` | Reads the Dionaea SQLite database, emits connection/login/malware events, captures binaries (SHA256 + VirusTotal + permanent archive) |
| `sync_dionaea.sh` | Pulls the Dionaea SQLite DB **and captured binaries** from the VPS, then runs the parser |
| `rebuild_geoip_cache.py` | Refreshes the shared GeoIP cache from MaxMind GeoLite2 |

## How It Works

Raw data from the VPS honeypots is synced to the Ubuntu Server every 15 minutes over
Tailscale. Parsers then transform it into the normalized JSON schema Wazuh expects.

```
VPS (DigitalOcean NYC1)
  nginx access.log     ──rsync──▶  /opt/cowrie-logs/nginx/access.log
  dionaea.sqlite       ──rsync──▶  /opt/cowrie-logs/dionaea/dionaea.sqlite
  dionaea binaries/    ──rsync──▶  /opt/cowrie-logs/dionaea/binaries/
        │
        ├─ parse_nginx.py     (*/15 cron)
        └─ sync_dionaea.sh    (systemd timer, every 15 min) ─▶ parse_dionaea.py
        │
        ▼
  /opt/cowrie-logs/wazuh/wazuh-nginx.json
  /opt/cowrie-logs/wazuh/wazuh-dionaea.json
        │
   Wazuh agent (localfile JSON reader)
        │
   OpenSearch  wazuh-alerts-4.x-*
        │
   /api/nginx  +  /api/dionaea  +  /api/threat_actors
        │
   Dashboard: Multi-Honeypot Intelligence + Threat Actor Correlation
```

## parse_nginx.py

**Input:** `/opt/cowrie-logs/nginx/access.log` (Combined Log Format)

- Parses each request: IP, timestamp, method, path, status, user-agent
- Classifies scanner types (IoT botnets, vuln scanners, curl clients, research scanners)
- Categorizes probe paths (.env theft, .git exposure, WordPress, Tomcat, Hikvision CVE, Log4Shell)
- Enriches source IPs with GeoIP (country, org, ASN) from the MaxMind cache
- Deduplicates: same IP + path + 1-minute window = one event

**Output fields:** `eventid, honeypot, src_ip, http_method, http_path, http_status, http_bytes, user_agent, scanner_type, path_category, location`

## parse_dionaea.py

**Input:** `/opt/cowrie-logs/dionaea/dionaea.sqlite` (Dionaea's structured event store)
plus the synced `binaries/` directory (one captured sample per file, named by MD5).

What it does:

- Reads the `connections` table for new entries since last run (stateful via `.parse_state_sqlite.json`)
- Joins `logins` to attach credential attempts to connection events
- Joins `downloads` → `connections` to attribute each **captured malware binary** to its
  source IP, service, and timestamp
- **Computes the real SHA256** from the captured file on disk (verifiable, VirusTotal-ready);
  falls back to the DB's MD5 if the file isn't synced, so a capture is never dropped
- **VirusTotal enrichment** (optional, `VT_API_KEY`): looks up each hash — *hash only, the
  sample is never uploaded* — and attaches detection ratio, threat label, and permalink.
  Results are cached so each hash is queried once; free-tier rate limits respected.
- **Permanent archive:** copies each new sample to `archive/YYYY-MM/<sha256>` (read-only,
  mode 400) with a JSON metadata sidecar (source IP, country, service, size, VT verdict),
  so samples survive index rollover and container rotation
- Hash-keyed dedup via a `seen_hashes` state list so each sample emits exactly once

**Output fields:** `eventid, honeypot, src_ip, src_port, dst_port, service, connection_id,
username, password, md5, sha256, file_size, download_url, vt_malicious, vt_total, vt_label,
vt_permalink, location`

> **Schema note:** Dionaea's `downloads` table stores `download_url` and `download_md5_hash`
> — there is **no `sha512` column**. The parser computes SHA256 itself from the captured
> file. (An earlier version queried a non-existent `sha512` column, which silently dropped
> every capture; see `docs/08-lessons-learned.md`.)

**Why SQLite instead of the log file:** Dionaea's text log is raw scapy packet-decode debug
output — gigabytes of protocol field dumps with no clean connection records. The SQLite
database is Dionaea's internal event store and holds structured connection, login, download,
and VirusTotal records regardless of log verbosity.

## Deployment

**nginx parser — cron (Ubuntu Server):**
```cron
# /etc/cron.d/honeypot-parsers
*/15 * * * * terickson python3 /opt/cowrie-tools/pipeline/parse_nginx.py >> /opt/wazuh-soc/logs/parse_nginx.log 2>&1
```

**Dionaea sync + parse — systemd timer (Ubuntu Server):**
```bash
# config/dionaea-sync.service + config/dionaea-sync.timer
sudo systemctl enable --now dionaea-sync.timer   # runs sync_dionaea.sh every 15 min
```
`sync_dionaea.sh` rsyncs the SQLite DB **and** the captured binaries from the VPS (key auth,
host/port/key supplied via environment), then runs `parse_dionaea.py`. To enable VirusTotal,
set `VT_API_KEY` in the service unit.

**Wazuh localfile config:** see `../config/wazuh-ossec-snippet.xml` for the `<localfile>`
entries added to `/var/ossec/etc/ossec.conf`.

**Wazuh rules:** see `../config/wazuh-honeypot-web-rules.xml` (IDs 100200–100360) covering
Dionaea and nginx events with MITRE mapping.

## Results (collection window May 21–29, 2026)

The Dionaea pipeline captured **7 unique malware binaries** over SMB **6 confirmed
WannaCry ransomware variants** (59–66 of ~76 VirusTotal engines flagging each) and one
trojan downloader, delivered from source IPs across multiple countries (United States,
Thailand, Sri Lanka, Vietnam). Each sample is SHA256-hashed, VirusTotal-verified, attributed
to its source, and preserved in the permanent archive. WannaCry continuing to self-propagate
over exposed SMB years after 2017 is a concrete illustration of long-tail internet threat
activity.
