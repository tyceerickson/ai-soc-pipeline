# 08 — Lessons Learned

## Overview

This document captures the key technical, operational, and analytical lessons learned during the design, build, and operation of this SOC pipeline. Several significant problems were encountered, diagnosed, and resolved — each one deepened understanding of the systems involved.

---

## Lesson 1: Disk Management in Production is Non-Negotiable

### What Happened
On May 24, 2026 at approximately 22:12 UTC, the DigitalOcean VPS ran out of disk space. The immediate cause was Dionaea generating ~600MB/hour of logs (compared to Cowrie's ~50MB/hour). The 24GB SSD filled completely in approximately 4 days. When the disk filled:
- Cowrie stopped logging new events
- The rsync job ran successfully but copied zero new data
- The Ubuntu Server continued running normally with no indication of the problem
- **~23 hours of attack data was permanently lost** (May 24 22:12 → May 25 21:39 UTC)

### Root Cause
Dionaea was logging raw protocol captures including binary SMB and FTP handshake data. Unlike Cowrie which logs structured JSON summaries, Dionaea logs complete packet captures that grow unboundedly.

### Resolution
Four independent safeguards were implemented:
1. **Post-rsync truncation** — after every rsync, the cron job truncates `dionaea.log` to zero bytes
2. **Hourly disk monitor** — if disk usage exceeds 70%, `dionaea.log` is emergency-truncated
3. **Logrotate** — weekly rotation with 2-file retention cap
4. **Docker log limits** — `/etc/docker/daemon.json` capped all container logs at 50MB max

### Takeaway
Monitoring disk space is as important as monitoring the security tools themselves. In a production SOC, this would be an alert condition — a sensor going silent is a critical gap in visibility, and the absence of logs is not the same as the absence of attacks.

---

## Lesson 2: OpenSearch Query Design Matters at Scale

### What Happened
Early versions of the dashboard used simple `match_all` queries with Python-side filtering. At 6 million alerts this was completely impractical — each API call retrieved thousands of records, parsed them in Python, and timed out.

### Resolution
All data aggregation was moved into OpenSearch using the aggregation API. A single query with nested aggregations (timeline, by_country, by_src_ip, by_eventid, mitre_tactics) returns all required data in one round trip in under 2 seconds:

```python
body = {
    "size": 0,  # No individual documents — aggregations only
    "track_total_hits": True,
    "aggs": {
        "by_country": {"terms": {"field": "data.location.country_name", "size": 100}},
        "by_src_ip":  {"terms": {"field": "data.src_ip", "size": 2000}},
        "timeline":   {"date_histogram": {...}},
        # ...
    }
}
```

### Takeaway
At millions of events, the difference between correct and incorrect query design is the difference between a 2-second response and a 60-second timeout. OpenSearch/Elasticsearch aggregations push computation to the data rather than pulling data to compute.

---

## Lesson 3: AI Models Have Real Hardware Constraints

### What Happened
`llama3.3:70b` was tested as an upgrade from `llama3.1:8b`. The 70B model produces noticeably better threat reasoning and more nuanced analysis. However, the RTX 4070 has only 8GB VRAM — insufficient to fit the full model. Ollama offloaded the excess to system RAM, and each inference call took 10-15 minutes instead of 15-30 seconds.

### Resolution
Reverted to `llama3.1:8b`, which fits entirely in VRAM. Compensated for the smaller model by improving prompt engineering — providing pre-aggregated statistics directly in the prompt rather than asking the model to reason from raw alert data:

```
# Instead of: "Here are 100 alerts, analyze them"
# We send:    "Total: 6.18M alerts. Top credential: root/3245gs5662d34 (103K×).
#              Top command: chattr -ia .ssh (90K×). Botnet: mdrfckr..."
```

The model still produces the raw alerts for pattern recognition, but the statistical context is pre-computed rather than inferred.

### Takeaway
Consumer GPU hardware is a real constraint for local LLM deployment. Quantization (Q4/Q8) and careful model selection matter. A smaller model with better-structured inputs often outperforms a larger model with poorly structured inputs.

---

## Lesson 4: Cowrie Accepts Everything — By Design

### What Happened
Initial analysis of the credential data showed a 63.3% "success" rate, which seemed extremely high and raised questions about data validity.

### Resolution
Cowrie is designed to accept all credentials — this is the fundamental honeypot mechanic. The "success" in `cowrie.login.success` means "Cowrie let the attacker in to the fake shell" not "the credential is valid on a real system." Every attacker eventually succeeds at "logging in," which is what makes Cowrie effective — attackers think they've compromised a real server and proceed to run their full playbook.

### Takeaway
Understanding what your data means requires understanding the tool that generates it. The 63.3% success rate is a data artifact, not a security finding. The valuable data is what attackers do *after* they log in.

---

## Lesson 5: rsync + File Rotation Requires Careful Ordering

### What Happened
After the disk outage was resolved, the consolidation command initially missed data because the order of log files in the `cat` command didn't account for the logrotate `.1` suffix used on the day boundaries.

### Resolution
The consolidation explicitly includes all file variants in chronological order:
```bash
cat cowrie.json.2026-05-21 \
    cowrie.json.2026-05-22 \
    cowrie.json.2026-05-23 \
    cowrie.json.2026-05-24 \
    cowrie.json.1 \        # Yesterday's midnight rotation
    cowrie.json            # Today's current file
```

### Takeaway
Log rotation creates multiple file formats (date-suffixed, numeric-suffixed, current). Any consolidation pipeline must account for all variants. A missing file silently produces an incomplete dataset.

---

## Lesson 6: Canvas Rendering Requires Layout to Complete First

### What Happened
The Geographic Attack Map used SVG innerHTML initially. When that had rendering issues, it was replaced with an HTML5 Canvas approach. However, the canvas rendered blank because `offsetWidth` returned 0 when queried immediately — the browser hadn't finished laying out the parent div before the drawing code ran.

### Resolution
Wrapped the drawing code in multiple `setTimeout` calls (0ms, 200ms, 500ms) to ensure at least one execution occurs after the browser completes its layout pass. The 500ms call is the reliable fallback.

### Takeaway
Browser rendering is asynchronous. Any JavaScript that measures DOM dimensions must wait for the layout phase to complete. `requestAnimationFrame` and `setTimeout` are the standard patterns for this.

---

## Lesson 7: Botnet Detection by Behavioral Signature

### What Happened
Initially, the botnet fingerprinting used simple IP-based clustering. But many botnets rotate their IP addresses constantly, making IP-based identification unreliable.

### Resolution
Switched to behavioral signatures — patterns in the credentials and commands used that are consistent across all IPs in the same campaign:
- **mdrfckr botnet:** Identified by the SSH public key string containing "mdrfckr"
- **345gs5662d34 campaign:** Identified by the distinctive credential string `3245gs5662d34`
- **Solana scanner:** Identified by exclusive use of `solana`/`sol` usernames

### Takeaway
Behavioral IOCs (Indicators of Compromise) are more durable than network IOCs. An attacker can change their IP easily; changing their payload or credential list requires retooling the entire campaign.
