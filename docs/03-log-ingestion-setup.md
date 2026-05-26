# 03 — Log Ingestion & Enrichment Pipeline

## Overview

Raw Cowrie logs are collected on the DigitalOcean VPS and transported to the Ubuntu Server every 15 minutes via rsync over Tailscale. On the Ubuntu Server, they are consolidated, enriched with geolocation data, and made available to Wazuh for indexing. The entire pipeline is automated and runs unattended.

---

## Stage 1: Collection (VPS)

### Cowrie Log Format
Cowrie writes one JSON object per line to `/home/cowrie/cowrie-data/log/cowrie.json`. Each event has a consistent structure:

```json
{
  "eventid": "cowrie.login.success",
  "timestamp": "2026-05-23T15:30:21.686037Z",
  "src_ip": "175.182.36.5",
  "src_port": 51234,
  "session": "abc123def456",
  "username": "root",
  "password": "3245gs5662d34",
  "sensor": "cowrie-nyc1"
}
```

Key event types and what they represent:

| Event ID | Meaning |
|----------|---------|
| `cowrie.session.connect` | New TCP connection established |
| `cowrie.client.kex` | SSH key exchange negotiated (attacker's SSH client fingerprint) |
| `cowrie.login.failed` | Credential attempt rejected by real system (accepted by Cowrie) |
| `cowrie.login.success` | Cowrie accepted the credential (all credentials succeed in Cowrie) |
| `cowrie.command.input` | Attacker typed a command |
| `cowrie.session.file_download` | Attacker downloaded a file from the honeypot |
| `cowrie.session.file_upload` | Attacker uploaded a file to the honeypot |
| `cowrie.session.closed` | Session ended |
| `cowrie.client.version` | Attacker's SSH client version string |

### Log Rotation
Cowrie rotates its log file daily at midnight UTC. The current day's log is always `cowrie.json`; previous days are `cowrie.json.YYYY-MM-DD`. This is important for the consolidation step.

---

## Stage 2: Transport (VPS → Ubuntu Server)

### Rsync Cron (`/etc/cron.d/cowrie-sync` on VPS)
```cron
*/15 * * * * root rsync -az --timeout=30 \
  /home/cowrie/cowrie-data/log/cowrie.json* \
  terickson@100.82.166.75:/opt/cowrie-logs/

*/15 * * * * root rsync -az --timeout=30 \
  /var/log/nginx/ \
  terickson@100.82.166.75:/opt/cowrie-logs/nginx/

*/15 * * * * root rsync -az --timeout=30 \
  /var/lib/dionaea/log/ \
  terickson@100.82.166.75:/opt/cowrie-logs/dionaea/ && \
  truncate -s 0 /var/lib/dionaea/log/dionaea.log
```

The Dionaea log is truncated after each sync to prevent it from filling the VPS disk. Dionaea was logging ~600MB/hour during peak periods and caused a full disk outage on May 24-25, 2026, resulting in ~23 hours of lost data.

### Disk Safety Monitor (`/etc/cron.d/disk-monitor` on VPS)
```cron
0 * * * * root USED=$(df / | awk 'NR==2{print $5}' | tr -d '%'); \
  if [ "$USED" -gt 70 ]; then \
    truncate -s 0 /var/lib/dionaea/log/dionaea.log; \
    docker logs --since 1h cowrie > /dev/null 2>&1; \
  fi
```

Triggers emergency truncation if disk usage exceeds 70%.

---

## Stage 3: Consolidation (Ubuntu Server)

### Hourly Cron (`/etc/cron.d/geoip-enrich` on Ubuntu Server)
```cron
0 * * * * terickson /opt/cowrie-tools/pipeline/consolidate_and_enrich.sh
0 6 * * 1 terickson /usr/bin/python3 /opt/cowrie-tools/pipeline/update_maxmind.py
```

### Consolidation Logic
The consolidation script cats all rotated log files into a single `cowrie.json`:

```bash
cat /opt/cowrie-logs/cowrie.json.2026-05-21 \
    /opt/cowrie-logs/cowrie.json.2026-05-22 \
    /opt/cowrie-logs/cowrie.json.2026-05-23 \
    /opt/cowrie-logs/cowrie.json.2026-05-24 \
    /opt/cowrie-logs/cowrie.json.1 \
    /opt/cowrie-logs/cowrie.json \
    > /opt/cowrie-logs/cowrie_all.json

cp /opt/cowrie-logs/cowrie_all.json /opt/cowrie-logs/cowrie.json
```

As of May 26, 2026 this produces **218,392 events** covering May 21-26.

---

## Stage 4: GeoIP Enrichment

### Script: `enrich_logs.py`
Reads `cowrie.json` line by line and resolves each unique `src_ip` using MaxMind GeoLite2 databases:

- **GeoLite2-City.mmdb** — resolves country, city, latitude, longitude
- **GeoLite2-ASN.mmdb** — resolves organization/ISP name and ASN number

Enriched events add these fields:
```json
{
  "src_country": "Indonesia",
  "src_city": "Mataram",
  "src_lat": -8.5833,
  "src_lon": 116.1167,
  "src_org": "Universitas Mataram",
  "src_asn": 45XXX
}
```

The script maintains a cache at `/opt/cowrie-logs/geoip_cache.json` mapping IP → GeoIP data. On each run it only resolves IPs not already in the cache, making subsequent runs fast.

**Current cache:** 944 IPs fully resolved.

### Output Files
```
/opt/cowrie-logs/cowrie.json           — consolidated raw events
/opt/cowrie-logs/cowrie_enriched.json  — GeoIP-enriched events (Wazuh reads this)
/opt/cowrie-logs/geoip_cache.json      — IP → GeoIP lookup cache
```

---

## Stage 5: Wazuh Indexing

The Wazuh agent monitors `cowrie_enriched.json` as a JSON log file. When new lines are appended, the agent forwards them to the Wazuh Manager, which applies custom decoders and rules (see `04-custom-rules.md`) before indexing into OpenSearch.

### Verify Ingestion is Working
```bash
# Check agent is sending events
tail -f /var/ossec/logs/ossec.log | grep cowrie

# Check OpenSearch is receiving them
curl -k -u admin:<password> \
  "https://localhost:9200/wazuh-alerts-4.x-*/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"exists":{"field":"data.honeypot"}}}'
```

---

## File Layout

```
/opt/cowrie-logs/
├── cowrie.json              # Consolidated raw Cowrie events (218K lines)
├── cowrie_enriched.json     # GeoIP-enriched (Wazuh reads this)
├── cowrie.json.1            # Yesterday's rotated log
├── cowrie.json.2026-05-21   # Per-day archives
├── cowrie.json.2026-05-22
├── cowrie.json.2026-05-23
├── cowrie.json.2026-05-24
├── geoip_cache.json         # 944-IP GeoIP cache
├── nginx/                   # Nginx access logs from VPS
├── dionaea/                 # Dionaea malware capture logs
└── wazuh/                   # Wazuh-formatted export files

/opt/cowrie-tools/
└── pipeline/
    ├── enrich_logs.py           # GeoIP enrichment
    ├── rebuild_geoip_cache.py   # Rebuild cache from scratch
    ├── export_to_wazuh.py       # Format for Wazuh ingestion
    └── update_maxmind.py        # Weekly MaxMind database update
```
