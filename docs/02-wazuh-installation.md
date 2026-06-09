# 02 — Wazuh Installation & Configuration

## Overview

Wazuh is deployed as an all-in-one installation on the Ubuntu Server (aarch64, Ubuntu 24.04). The stack includes the Wazuh Manager, Wazuh Indexer (OpenSearch), and Wazuh Dashboard, all on the same host, installed via the official Wazuh quickstart script for single-node deployment.

---

## Installation

### System Requirements
- Ubuntu 24.04 LTS (aarch64)
- 64GB RAM (Wazuh indexer uses ~4–8GB under normal load)
- 98GB disk (66% used as of May 29, 2026)
- Tailscale installed and authenticated

### Install Command
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
bash wazuh-install.sh -a
```

The `-a` flag installs all components (manager, indexer, dashboard) in one step. Installation takes ~10–15 minutes. On completion the installer prints admin credentials, save them immediately.

### Credentials
The installer-generated credentials (dashboard `admin`, API `wazuh`, OpenSearch `admin`) are **not stored in this repository**. In this project the OpenSearch password is supplied to every consumer (dashboard, parsers, triage, cron) via the `OPENSEARCH_PASS` environment variable — set in the relevant systemd unit or cron file, never hardcoded in source. See `08-lessons-learned.md` for the migration from hardcoded credentials to environment variables.

---

## Post-Installation Configuration

### 1. Verify Services
```bash
systemctl status wazuh-manager
systemctl status wazuh-indexer
systemctl status wazuh-dashboard
```

All three should show `active (running)`. If the indexer takes more than 60 seconds on first boot, that is normal, OpenSearch performs index recovery which takes a minute or two.

### 2. Confirm OpenSearch is Accessible
```bash
curl -k -u admin:"$OPENSEARCH_PASS" https://localhost:9200/_cluster/health?pretty
```

Expected `status: "green"` or `"yellow"` (yellow is normal for single-node deployments with no replica shards).

### 3. Confirm Alert Index Exists
```bash
curl -k -u admin:"$OPENSEARCH_PASS" \
  "https://localhost:9200/_cat/indices/wazuh-alerts-4.x-*?v"
```

After the pipeline is active you'll see daily indices like `wazuh-alerts-4.x-2026.05.22`.

---

## Wazuh Agent Setup (Local)

All log ingestion runs on the same machine as the Wazuh Manager, so a local agent forwards the honeypot JSON feeds to the manager.

### Register Local Agent
```bash
/var/ossec/bin/manage_agents
# (A) to add agent · Name: homeserver-cowrie · IP: 127.0.0.1 · note the key
```

### Configure Agent to Monitor the Honeypot Feeds
Edit `/var/ossec/etc/ossec.conf` and add inside `<ossec_config>` (see `config/wazuh-ossec-snippet.xml`):
```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/cowrie-logs/wazuh/wazuh-cowrie.json</location>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/opt/cowrie-logs/wazuh/wazuh-nginx.json</location>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/opt/cowrie-logs/wazuh/wazuh-dionaea.json</location>
</localfile>
```

### Restart Agent
```bash
systemctl restart wazuh-agent
```

---

## Index Lifecycle Management

Wazuh creates a daily index (`wazuh-alerts-4.x-YYYY.MM.DD`). For a single-node lab with limited disk, set a retention policy to prevent disk exhaustion.

```bash
# List indices by size
curl -k -u admin:"$OPENSEARCH_PASS" \
  "https://localhost:9200/_cat/indices/wazuh-alerts-4.x-*?v&s=index"

# Manual deletion (if needed)
curl -k -u admin:"$OPENSEARCH_PASS" -X DELETE \
  "https://localhost:9200/wazuh-alerts-4.x-2026.05.13"
```

---

## SSL Certificate Note

The Wazuh dashboard and OpenSearch use self-signed certificates generated during installation. Internal API calls from the Flask dashboard use `ssl.CERT_NONE`:

```python
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
```

Acceptable for an internal lab where all traffic stays within the Tailscale mesh. A production deployment would use certificates from a trusted CA.

---

## Wazuh Dashboard Access

The Wazuh dashboard is at `https://100.82.166.75` (Tailscale only): real-time alert visualization, agent management, rule/decoder management, the built-in MITRE ATT&CK module. In this project it is used primarily for rule development and verification — all production visualization is handled by the custom Flask dashboard.
