# 03 — Log Ingestion & Enrichment Pipeline

## Overview

Raw data from three honeypots is collected on the DigitalOcean VPS and transported to the Ubuntu Server every 15 minutes over Tailscale. On the Ubuntu Server it is consolidated, enriched (GeoIP + VirusTotal), normalized to Wazuh JSON, and indexed. The pipeline is fully automated and runs unattended.

---

## Stage 1: Collection (VPS)

### Cowrie (SSH/Telnet)
Cowrie writes one JSON object per line. Example:
```json
{
  "eventid": "cowrie.login.success",
  "timestamp": "2026-05-23T15:30:21.686037Z",
  "src_ip": "175.182.36.5",
  "session": "abc123def456",
  "username": "root",
  "password": "345gs5662d34",
  "sensor": "cowrie-nyc1"
}
```

| Event ID | Meaning |
|----------|---------|
| `cowrie.session.connect` | New TCP connection |
| `cowrie.client.kex` | SSH key exchange (attacker client fingerprint) |
| `cowrie.login.failed` | Credential rejected (real systems) / still recorded by Cowrie |
| `cowrie.login.success` | Cowrie accepted the credential (all succeed by design) |
| `cowrie.command.input` | Attacker typed a command |
| `cowrie.session.file_download` / `file_upload` | File transfer |
| `cowrie.session.closed` | Session ended |

### nginx (web)
Standard Combined Log Format access log, parsed by `parse_nginx.py`.

### Dionaea (malware capture)
Dionaea records connections, logins, **downloads (captured malware)**, and optional VirusTotal results in a SQLite database (`dionaea.sqlite`), and saves each captured binary to a `binaries/` directory named by its MD5. The text log is unstructured scapy debug noise and is **not** used for parsing — the SQLite store is the source of truth.

### Log Rotation
Cowrie rotates daily at midnight UTC: current day is `cowrie.json`, previous days are `cowrie.json.YYYY-MM-DD`. This matters for the consolidation step.

---

## Stage 2: Transport (VPS → Ubuntu Server)

### Cowrie / nginx — rsync cron (`/etc/cron.d/cowrie-sync` on VPS)
```cron
*/15 * * * * root rsync -az --timeout=30 \
  /home/cowrie/cowrie-data/log/cowrie.json* \
  terickson@100.82.166.75:/opt/cowrie-logs/

*/15 * * * * root rsync -az --timeout=30 \
  /var/log/nginx/ \
  terickson@100.82.166.75:/opt/cowrie-logs/nginx/
```

### Dionaea — systemd timer (`dionaea-sync.timer` on Ubuntu Server)
Rather than a VPS-side push, the SIEM **pulls** Dionaea data so it can also fetch the captured binaries and run the parser in one step. `sync_dionaea.sh` (run every 15 min by the timer):
1. rsyncs `dionaea.sqlite` from the VPS
2. rsyncs the `binaries/` directory (`--ignore-existing`, append-only)
3. runs `parse_dionaea.py`, which emits Wazuh events, computes SHA256, looks up VirusTotal, and archives new samples

Host/port/key for the sync are supplied via environment variables in `config/dionaea-sync.service` — no infrastructure details are committed to source.

### Disk Safety Monitor (`/etc/cron.d/disk-monitor` on VPS)
```cron
0 * * * * root USED=$(df / | awk 'NR==2{print $5}' | tr -d '%'); \
  if [ "$USED" -gt 70 ]; then truncate -s 0 /var/lib/dionaea/log/dionaea.log; fi
```
Emergency truncation if disk usage exceeds 70%. Dionaea's text log grew ~600MB/hour and caused a full-disk outage on May 24–25, 2026 (~23 hours of lost data). Note: this truncates only the unused **text** log; the SQLite store and captured binaries are preserved.

---

## Stage 3: Consolidation (Ubuntu Server)

### Hourly Cron (`/etc/cron.d/geoip-enrich`)
```cron
OPENSEARCH_PASS=<set-in-cron-env>
0 * * * * terickson /opt/cowrie-tools/pipeline/consolidate_and_enrich.sh
0 6 * * 1 terickson /usr/bin/python3 /opt/cowrie-tools/pipeline/update_maxmind.py
```

### Consolidation Logic
```bash
cat /opt/cowrie-logs/cowrie.json.2026-05-21 \
    /opt/cowrie-logs/cowrie.json.2026-05-22 \
    ... \
    /opt/cowrie-logs/cowrie.json.1 \
    /opt/cowrie-logs/cowrie.json \
    > /opt/cowrie-logs/cowrie_all.json
cp /opt/cowrie-logs/cowrie_all.json /opt/cowrie-logs/cowrie.json
```
Across the May 21–29 window this yields **872,871 Cowrie events**.

---

## Stage 4: Enrichment

### GeoIP (`enrich_logs.py` / `rebuild_geoip_cache.py`)
Resolves each unique `src_ip` against MaxMind GeoLite2 (City + ASN), adding country, city, lat/lon, org, and ASN. Results are cached in `/opt/cowrie-logs/geoip_cache.json`; only uncached IPs are resolved on each run.

### VirusTotal (captured malware, in `parse_dionaea.py`)
For each captured binary, the parser computes the real **SHA256** from the file on disk and looks the hash up on VirusTotal — *hash only; the sample is never uploaded*. The detection ratio, threat label, and permalink are attached to the event and recorded in the permanent archive sidecar. Lookups are cached so each hash is queried once; free-tier rate limits are respected. Enable by setting `VT_API_KEY` in `config/dionaea-sync.service`.

### Permanent Malware Archive
Each new sample is copied to `/opt/cowrie-logs/dionaea/archive/YYYY-MM/<sha256>` (read-only, mode 400) with a JSON metadata sidecar (source IP, country, service, size, VT verdict) — surviving index rollover and container rotation.

---

## Stage 5: Wazuh Indexing

The Wazuh agent monitors the JSON feeds (`cowrie_enriched.json`, `wazuh-nginx.json`, `wazuh-dionaea.json`). New lines are forwarded to the manager, which applies custom decoders/rules (see `04-custom-rules.md`) before indexing into OpenSearch.

```bash
# agent activity
tail -f /var/ossec/logs/ossec.log | grep -E 'cowrie|dionaea|nginx'

# malware capture events in the index
curl -k -u admin:"$OPENSEARCH_PASS" \
  "https://localhost:9200/wazuh-alerts-4.x-*/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"data.eventid":"dionaea.binary.captured"}}}'
```

---

## File Layout

```
/opt/cowrie-logs/
├── cowrie.json                 # Consolidated raw Cowrie events
├── cowrie_enriched.json        # GeoIP-enriched (Wazuh reads this)
├── cowrie.json.2026-05-2x      # Per-day archives
├── geoip_cache.json            # IP → GeoIP cache
├── nginx/                      # nginx access logs from VPS
├── dionaea/
│   ├── dionaea.sqlite          # Dionaea event store (synced from VPS)
│   ├── binaries/               # captured malware (named by MD5)
│   ├── archive/YYYY-MM/        # permanent SHA256-named samples + .json sidecars
│   └── .parse_state_sqlite.json
└── wazuh/
    ├── wazuh-nginx.json
    └── wazuh-dionaea.json

/opt/cowrie-tools/pipeline/
├── enrich_logs.py              # GeoIP enrichment
├── rebuild_geoip_cache.py      # rebuild GeoIP cache
├── parse_nginx.py              # nginx CLF → Wazuh JSON
├── parse_dionaea.py            # Dionaea SQLite → Wazuh JSON (+SHA256/VT/archive)
├── sync_dionaea.sh             # VPS pull (sqlite+binaries) → parse
├── export_to_wazuh.py          # format helpers
└── update_maxmind.py           # weekly MaxMind update
```
