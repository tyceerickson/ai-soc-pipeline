# Operations Runbook

Operational notes for the AI-Powered SOC Pipeline, this covers the components that live
outside the git repo and must be re-applied after rebuilds/upgrades, plus the
automated ingestion topology and resilience safeguards.

## Ingestion topology (all homeserver-owned, reboot-safe)

Each honeypot has its own systemd timer on the SIEM/homeserver that pulls data from the
DigitalOcean VPS over Tailscale and emits `{"data":{...}}`-wrapped Wazuh JSON:

| Honeypot | Timer | Script | Cadence |
|----------|-------|--------|---------|
| Cowrie (SSH) | `cowrie-sync.timer` | `sync_cowrie.sh` → `forward_cowrie.py` | 5 min |
| nginx (web) | `nginx-sync.timer` | `sync_nginx.sh` → `parse_nginx.py` | 5 min |
| Dionaea (malware) | `dionaea-sync.timer` | `sync_dionaea.sh` → `parse_dionaea.py` | 15 min |

All timers are `Persistent=true` and `enabled` for boot. Wazuh tails the resulting
`/opt/cowrie-logs/wazuh/wazuh-{cowrie,nginx,dionaea}.json` feeds.

Verify all timers are scheduled and enabled:
```
systemctl list-timers --all | grep -E 'cowrie|nginx|dionaea'
for s in cowrie-sync.timer nginx-sync.timer dionaea-sync.timer wazuh-manager filebeat soc-dashboard; do
  echo "$s: $(systemctl is-enabled $s) / $(systemctl is-active $s)"; done
```

## Non-git artifacts — RE-APPLY after a rebuild/upgrade

These are not (and cannot be) tracked in git as live config; the repo holds reproducible
copies under `config/`. Re-apply them in these situations:

### 1. OpenSearch ingest pipeline  (re-apply if the indexer/pipeline is rebuilt)
The Wazuh alerts ingest pipeline includes a Painless processor that flattens
`data.data.* → data.*`. Without it, enriched honeypot docs are silently dropped on a
keyword mapping conflict (`Can't get text on a START_OBJECT`).

Reproducible copy: `config/ingest-pipeline-filebeat-wazuh-alerts.json`

Re-import:
```
curl -sk -u "admin:$OPENSEARCH_PASS" -X PUT \
  "https://127.0.0.1:9200/_ingest/pipeline/filebeat-7.10.2-wazuh-alerts-pipeline" \
  -H 'Content-Type: application/json' \
  --data-binary @config/ingest-pipeline-filebeat-wazuh-alerts.json
```

### 2. MITRE DB tactic-mapping fix  (RE-APPLY after every Wazuh upgrade)
Wazuh resolves a rule's technique to ALL tactics MITRE links to it via
`/var/ossec/var/db/mitre.db`. T1078 (Valid Accounts) maps to 4 tactics, which
over-tagged every successful login. The fix prunes T1078 to Initial Access only;
combined with T1110 in rule 100112 a login resolves to
`[Credential Access, Initial Access]`. **Wazuh upgrades regenerate mitre.db and revert
this.**

Reproducible copy: `config/mitre-db-fixes.sql`

Re-apply:
```
sudo systemctl stop wazuh-manager
sudo sqlite3 /var/ossec/var/db/mitre.db < config/mitre-db-fixes.sql
sudo systemctl start wazuh-manager
# verify:
echo '{"data":{"honeypot":"cowrie","eventid":"cowrie.login.success","username":"root","password":"x","src_ip":"1.2.3.4"}}' \
  | sudo /var/ossec/bin/wazuh-logtest   # -> mitre.tactic ['Credential Access','Initial Access']
```

### 3. fail2ban tailnet whitelist (on the VPS)
The VPS runs fail2ban on sshd. Rapid sync reconnections previously got the homeserver's
Tailscale IP banned ("connection refused" with SYN arriving but rejected). Whitelist the
whole tailnet in `/etc/fail2ban/jail.local` on the VPS:
```
[DEFAULT]
ignoreip = 127.0.0.1/8 100.64.0.0/10
```
Then `sudo systemctl restart fail2ban` and confirm `fail2ban-client get sshd ignoreip`.

## Resilience safeguards (built in)
- **Sync scripts never truncate local data when the VPS is unreachable.** Each
  `sync_*.sh` checks remote size; if 0/unreachable it exits without modifying the local
  feed (prevents the logcollector tail from being wiped on a network blip).
- **alerts.json rotation** capped (monitord) so it can't bloat and stall Filebeat.
- **Rule-file hygiene:** never leave a `*.bak` file in `/var/ossec/etc/rules/` — Wazuh
  loads it as an active ruleset and causes duplicate-ID conflicts. All backups go to
  `/opt/wazuh-soc/rule-backups/`.

## Detection ruleset
57 custom rules, 27 distinct MITRE ATT&CK techniques across ~12 tactics:
- `config/wazuh-cowrie-rules.xml` — 29 rules, IDs 100100–100191
- `config/wazuh-honeypot-web-rules.xml` — 28 rules, IDs 100200–100344

Rebuilt June 2026 for per-behavior MITRE accuracy: each rule tags the single correct
technique/tactic for the behavior it detects, grounded in the lab's real captured TTPs.
Validate after any change: `sudo /var/ossec/bin/wazuh-analysisd -t` then restart
wazuh-manager.

## Known redundancy
A LAN machine (192.168.10.1) historically rsync'd the nginx access.log hourly. The
homeserver-owned `nginx-sync.timer` (5 min) now supersedes it; the old hourly job is
harmless redundancy and can be removed at your convenience.
