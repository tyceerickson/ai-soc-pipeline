# 03 — Log Ingestion & Enrichment Pipeline

## Overview

Raw data from three honeypots is collected on the DigitalOcean VPS and pulled to the Ubuntu Server over Tailscale by homeserver-owned systemd timers. With Cowrie and nginx being pulled every 5 minutes, with Dionaea being pulled every 15 minutes. On the Ubuntu Server it is consolidated, enriched (GeoIP + VirusTotal), normalized to `{"data":{...}}`-wrapped Wazuh JSON, and indexed. The pipeline is fully automated, reboot-safe, and runs unattended.

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
Dionaea records connections, logins, **downloads (captured malware)**, and optional VirusTotal results in a SQLite database (`dionaea.sqlite`), and saves each captured binary to a `binaries/` directory named by its MD5. The text log is unstructured scapy debug noise and is **not** used for parsing, the SQLite store is the source of truth.

### Log Rotation
Cowrie rotates daily at midnight UTC: current day is `cowrie.json`, previous days are `cowrie.json.YYYY-MM-DD`. This matters for the consolidation step.

---

## Stage 2: Transport (VPS → Ubuntu Server)

All three honeypots are now **pulled by homeserver-owned systemd timers** (not VPS-side cron). Each timer runs a sync script that rsyncs the honeypot's data from the VPS over Tailscale, then runs its parser/forwarder. This makes the homeserver the single owner of ingestion (auditable via `systemctl list-timers`), with no dependency on external machines.

| Honeypot | Timer | Script | Cadence |
|----------|-------|--------|---------|
| Cowrie | `cowrie-sync.timer` | `sync_cowrie.sh` → `forward_cowrie.py` | 5 min |
| nginx | `nginx-sync.timer` | `sync_nginx.sh` → `parse_nginx.py` | 5 min |
| Dionaea | `dionaea-sync.timer` | `sync_dionaea.sh` → `parse_dionaea.py` | 15 min |

### Cowrie — `sync_cowrie.sh`
`rsync --append` of the VPS `cowrie.json` (append-preserves the inode Wazuh's logcollector tails), then `forward_cowrie.py` reads new lines and appends them **wrapped as `{"data": {...}}`** — to `wazuh-cowrie.json`. Includes an unreachable/rotation guard (below).

### nginx — `sync_nginx.sh`
`rsync` of the VPS nginx `access.log`, then `parse_nginx.py` converts Combined Log Format to `{"data":{...}}`-wrapped Wazuh JSON in `wazuh-nginx.json`. (Replaced an earlier fragile hourly rsync owned by a separate LAN machine.)

### Dionaea — `sync_dionaea.sh` (systemd timer)
The SIEM **pulls** Dionaea data so it can also fetch captured binaries and run the parser in one step:
1. rsyncs `dionaea.sqlite` from the VPS
2. rsyncs the `binaries/` directory (`--ignore-existing`, append-only)
3. runs `parse_dionaea.py`, which emits wrapped Wazuh events, computes SHA256, looks up VirusTotal, and archives new samples

Host/port/key for the syncs are supplied via environment/script variables there are no infrastructure details are committed to source.

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
For each captured binary, the parser computes the real **SHA256** from the file on disk and looks the hash up on VirusTotal *hash only; the malware sample is never uploaded*. The detection ratio, threat label, and permalink are attached to the event and recorded in the permanent archive sidecar. Lookups are cached so each hash is queried once; free-tier rate limits are respected. Enable by setting `VT_API_KEY` in `config/dionaea-sync.service`.

### Permanent Malware Archive
Each new sample is copied to `/opt/cowrie-logs/dionaea/archive/YYYY-MM/<sha256>` (read-only, mode 400) with a JSON metadata sidecar (source IP, country, service, size, VT verdict) — surviving index rollover and container rotation.

---

## Stage 5: Wazuh Indexing

Wazuh's logcollector tails the wrapped JSON feeds (`wazuh-cowrie.json`, `wazuh-nginx.json`, `wazuh-dionaea.json`). New lines are decoded (fields exposed as `data.*`), matched against the custom rules (see `04-custom-rules.md`), and indexed into OpenSearch. An OpenSearch **ingest pipeline** (`filebeat-7.10.2-wazuh-alerts-pipeline`) runs a Painless processor that flattens a legacy double-nested `data.data.*` → `data.*` edge case before indexing, without it, wrapped events hit a keyword mapping conflict and are silently dropped.

```bash
# logcollector activity
tail -f /var/ossec/logs/ossec.log | grep -E 'cowrie|dionaea|nginx'

# malware capture events in the index
curl -k -u admin:"$OPENSEARCH_PASS" \
  "https://localhost:9200/wazuh-alerts-4.x-*/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"data.eventid":"dionaea.binary.captured"}}}'
```

---

## Hardening & Resilience

Lessons baked into the pipeline after real operational failures:

- **`{"data":{...}}` wrapping is mandatory.** Parsers/forwarders wrap every event so Wazuh decodes `data.*` and the rules match. A flat (unwrapped) event matches no rule and produces zero alerts, this silently took nginx/dionaea offline once until corrected.
- **Ingest-pipeline flatten guard.** The OpenSearch pipeline's Painless processor handles the `data.data.*` double-nest edge case; missing it caused enriched docs to be silently dropped at index time (`Can't get text on a START_OBJECT`).
- **Sync scripts never truncate on an unreachable VPS.** Each `sync_*.sh` checks the remote file size first; if it's `0`/unreachable, the script exits without modifying the local feed. (An earlier bug truncated the local log on every failed run during a network blip, wiping the logcollector tail.)
- **fail2ban tailnet whitelist.** Rapid sync reconnections once tripped the VPS's fail2ban and banned the homeserver's Tailscale IP (SYN arrived but was refused). `/etc/fail2ban/jail.local` on the VPS now sets `ignoreip = 127.0.0.1/8 100.64.0.0/10` to exempt the whole tailnet.
- **alerts.json rotation capped** (monitored) so the file can't bloat and stall Filebeat's harvester.
- **No `.bak` files in `/var/ossec/etc/rules/`.** Wazuh loads any `.xml`-ish file there as an active ruleset, causing duplicate-ID conflicts; all backups go to `/opt/wazuh-soc/rule-backups/`.
- **MITRE-DB tactic fix is non-git and reverts on upgrade.** See `operations.md` — `config/mitre-db-fixes.sql` must be re-applied after any Wazuh upgrade.

---

## File Layout

```
/opt/cowrie-logs/
├── cowrie.json                 # Synced raw Cowrie events (rsync --append target)
├── cowrie.json.2026-05-2x      # Per-day archives
├── geoip_cache.json            # IP → GeoIP cache
├── nginx/                      # nginx access logs from VPS
├── dionaea/
│   ├── dionaea.sqlite          # Dionaea event store (synced from VPS)
│   ├── binaries/               # captured malware (named by MD5)
│   ├── archive/YYYY-MM/        # permanent SHA256-named samples + .json sidecars
│   └── .parse_state_sqlite.json
└── wazuh/                      # the wrapped feeds Wazuh tails
    ├── wazuh-cowrie.json
    ├── wazuh-nginx.json
    └── wazuh-dionaea.json

/opt/cowrie-tools/pipeline/
├── enrich_logs.py              # GeoIP enrichment
├── rebuild_geoip_cache.py      # rebuild GeoIP cache
├── parse_nginx.py              # nginx CLF → wrapped Wazuh JSON
├── parse_dionaea.py            # Dionaea SQLite → wrapped Wazuh JSON (+SHA256/VT/archive)
├── forward_cowrie.py           # wrap + append Cowrie events to wazuh-cowrie.json
├── sync_cowrie.sh              # VPS pull (cowrie.json, --append + guard) → forward
├── sync_nginx.sh               # VPS pull (access.log) → parse
├── sync_dionaea.sh             # VPS pull (sqlite+binaries) → parse
├── export_to_wazuh.py          # format helpers
└── update_maxmind.py           # weekly MaxMind update
```
