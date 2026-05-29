# Pipeline — Log Parsers

This directory contains the Python parsers that convert raw honeypot logs into
Wazuh-compatible JSON for ingestion into OpenSearch.

## Files

| File | Purpose |
|------|---------|
| `parse_nginx.py` | Parses nginx Combined Log Format access logs into structured JSON events |
| `parse_dionaea.py` | Queries the Dionaea SQLite database and exports connection events as JSON |

## How It Works

Raw logs from the VPS honeypots are synced to the Ubuntu Server every 15 minutes
via rsync over Tailscale. These parsers then run as cron jobs to transform that
raw data into the normalized JSON schema that Wazuh expects.

```
VPS (DigitalOcean NYC1)
  nginx access.log  ──rsync──▶  /opt/cowrie-logs/nginx/access.log
  dionaea.sqlite    ──rsync──▶  /opt/cowrie-logs/dionaea/dionaea.sqlite
                                        │
                              parse_nginx.py (*/15 cron)
                              parse_dionaea.py (*/15 cron)
                                        │
                              /opt/cowrie-logs/wazuh/wazuh-nginx.json
                              /opt/cowrie-logs/wazuh/wazuh-dionaea.json
                                        │
                              Wazuh agent (localfile JSON reader)
                                        │
                              OpenSearch wazuh-alerts-4.x-*
                                        │
                              /api/nginx + /api/dionaea + /api/honeypots
                                        │
                              Dashboard Multi-Honeypot Intelligence panel
```

## parse_nginx.py

**Input:** `/opt/cowrie-logs/nginx/access.log` (Combined Log Format)

**What it does:**
- Parses each request line: IP, timestamp, method, path, status, user-agent
- Classifies scanner types: IoT botnets, vuln scanners, curl clients, research scanners
- Categorizes probe paths: `.env` theft, `.git` exposure, WordPress, Tomcat, Hikvision CVE, Log4Shell
- Enriches source IPs with GeoIP (country, org, ASN) from MaxMind cache
- Deduplicates: same IP + path + 1-minute window = one event
- Writes one JSON event per line to `wazuh-nginx.json`

**Output fields:** `eventid`, `honeypot`, `src_ip`, `http_method`, `http_path`,
`http_status`, `http_bytes`, `user_agent`, `scanner_type`, `path_category`, `location`

## parse_dionaea.py

**Input:** `/opt/cowrie-logs/dionaea/dionaea.sqlite` (Dionaea's structured event database)

**What it does:**
- Queries the `connections` table for new entries since last run (stateful via `.parse_state_sqlite.json`)
- Joins with `logins` table to attach credential attempts to connection events
- Joins with `downloads` table to flag malware binary captures with SHA512 hash
- Enriches source IPs with GeoIP
- Deduplicates: same IP + service + 1-minute window = one event
- Writes one JSON event per line to `wazuh-dionaea.json`

**Output fields:** `eventid`, `honeypot`, `src_ip`, `src_port`, `dst_port`,
`service`, `connection_id`, `username`, `password`, `sha512`, `location`

**Why SQLite instead of log file:** Dionaea's text log is 100% raw scapy
packet-decode debug noise — 1.4GB of TDS header field dumps with no
structured connection data. The SQLite database (`dionaea.sqlite`) is
Dionaea's internal event store and contains clean, structured connection
records regardless of log verbosity settings.

## Deployment

### Cron (Ubuntu Server)

```
# /etc/cron.d/honeypot-parsers
*/15 * * * * terickson python3 /opt/cowrie-tools/pipeline/parse_nginx.py >> /opt/wazuh-soc/logs/parse_nginx.log 2>&1
*/15 * * * * terickson python3 /opt/cowrie-tools/pipeline/parse_dionaea.py >> /opt/wazuh-soc/logs/parse_dionaea.log 2>&1
```

### rsync (VPS cron — /etc/cron.d/cowrie-sync)

```
*/15 * * * * root rsync -av -e 'ssh -i /root/.ssh/cowrie_sync ...' \
  /opt/cowrie/nginx-logs/ terickson@192.168.10.4:/opt/cowrie-logs/nginx/
*/15 * * * * root rsync -av -e 'ssh -i /root/.ssh/cowrie_sync ...' \
  /opt/cowrie/dionaea-data/dionaea.sqlite \
  terickson@192.168.10.4:/opt/cowrie-logs/dionaea/dionaea.sqlite
```

### Wazuh localfile config

See `../config/wazuh-ossec-snippet.xml` for the `<localfile>` entries to add
to `/var/ossec/etc/ossec.conf`.

### Wazuh rules

See `../config/wazuh-honeypot-web-rules.xml` for the detection rules
(IDs 100200–100360) covering Dionaea and nginx events with MITRE mapping.
