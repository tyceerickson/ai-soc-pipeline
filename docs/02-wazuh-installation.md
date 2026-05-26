# 02 — Wazuh Installation & Configuration

## Overview

Wazuh is deployed as an all-in-one installation on the Ubuntu Server (aarch64, Ubuntu 24.04). The stack includes the Wazuh Manager, Wazuh Indexer (OpenSearch), and Wazuh Dashboard, all running on the same host. The installation uses the official Wazuh quickstart script for single-node deployment.

---

## Installation

### System Requirements
- Ubuntu 24.04 LTS (aarch64)
- 64GB RAM (Wazuh indexer uses ~4-8GB under normal load)
- 98GB disk (64% used as of May 26, 2026)
- Tailscale installed and authenticated

### Install Command
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
bash wazuh-install.sh -a
```

The `-a` flag installs all components (manager, indexer, dashboard) in one step. Installation takes approximately 10-15 minutes. Upon completion, the installer prints credentials for the admin user — these must be saved immediately.

### Credentials (saved separately)
- **Dashboard:** `https://100.82.166.75` — `admin / <password>`
- **API (port 55000):** `wazuh / <password>`
- **OpenSearch (port 9200):** `admin / <password>`

---

## Post-Installation Configuration

### 1. Verify Services
```bash
systemctl status wazuh-manager
systemctl status wazuh-indexer
systemctl status wazuh-dashboard
```

All three should show `active (running)`. If the indexer takes more than 60 seconds to start, it is normal — OpenSearch performs index recovery on first boot.

### 2. Confirm OpenSearch is Accessible
```bash
curl -k -u admin:<password> https://localhost:9200/_cluster/health?pretty
```

Expected output shows `status: "green"` or `status: "yellow"` (yellow is normal for single-node deployments with no replica shards).

### 3. Confirm Alert Index Exists
```bash
curl -k -u admin:<password> \
  "https://localhost:9200/_cat/indices/wazuh-alerts-4.x-*?v"
```

This lists all alert indices. After the honeypot pipeline is active you will see daily indices like `wazuh-alerts-4.x-2026.05.22`.

---

## Wazuh Agent Setup (Local)

Since all log ingestion runs on the same machine as the Wazuh Manager, a local agent is used. The agent monitors the enriched Cowrie log file and forwards events to the manager.

### Register Local Agent
```bash
/var/ossec/bin/manage_agents
# Choose (A) to add agent
# Name: homeserver-cowrie
# IP: 127.0.0.1
# Note the key generated
```

### Configure Agent to Monitor Cowrie Logs
Edit `/var/ossec/etc/ossec.conf` and add inside `<ossec_config>`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/cowrie-logs/cowrie_enriched.json</location>
</localfile>
```

### Restart Agent
```bash
systemctl restart wazuh-agent
```

---

## Index Lifecycle Management

By default, Wazuh creates a new daily index (`wazuh-alerts-4.x-YYYY.MM.DD`). For a single-node lab setup with limited disk, it is advisable to set a retention policy to prevent disk exhaustion.

### Check Current Index Size
```bash
curl -k -u admin:<password> \
  "https://localhost:9200/_cat/indices/wazuh-alerts-4.x-*?v&s=index"
```

### Manual Index Deletion (if needed)
```bash
curl -k -u admin:<password> -X DELETE \
  "https://localhost:9200/wazuh-alerts-4.x-2026.05.13"
```

---

## SSL Certificate Note

The Wazuh dashboard and OpenSearch use self-signed certificates generated during installation. All internal API calls from the Flask dashboard use `ssl.CERT_NONE` verification:

```python
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
```

This is acceptable for an internal lab environment where all traffic stays within the Tailscale mesh. In a production environment, certificates from a trusted CA would be required.

---

## Wazuh Dashboard Access

The Wazuh dashboard is accessible at `https://100.82.166.75` (Tailscale only). It provides:
- Real-time alert visualization
- Agent management
- Rule and decoder management
- Built-in MITRE ATT&CK module
- Vulnerability detection (not used in this project)

For this project, the Wazuh dashboard is used primarily for rule development and verification. All production visualization is handled by the custom Flask dashboard.
