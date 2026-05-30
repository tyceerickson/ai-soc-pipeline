# 08 — Lessons Learned

## Overview

This document captures the key technical, operational, and analytical lessons learned during the design, build, and operation of this SOC pipeline. Several significant problems were encountered, diagnosed, and resolved — each deepened understanding of the systems involved.

---

## Lesson 1: Disk Management in Production is Non-Negotiable

### What Happened
On May 24, 2026 at ~22:12 UTC, the DigitalOcean VPS ran out of disk space. The cause was Dionaea generating ~600MB/hour of raw protocol logs (vs Cowrie's ~50MB/hour); the 24GB SSD filled in ~4 days. When the disk filled, Cowrie stopped logging, rsync copied zero new data, the Ubuntu Server showed no problem, and **~23 hours of attack data was permanently lost** (May 24 22:12 → May 25 21:39 UTC).

### Root Cause
Dionaea was logging raw packet captures (binary SMB/FTP handshake data) that grow unboundedly, unlike Cowrie's structured JSON summaries.

### Resolution
Four safeguards: (1) post-rsync truncation of `dionaea.log`; (2) hourly disk monitor that emergency-truncates above 70%; (3) logrotate with a 2-file cap; (4) Docker log limits (50MB max) in `/etc/docker/daemon.json`. Crucially, only the **unused text log** is truncated — the Dionaea SQLite store and captured binaries are preserved.

### Takeaway
Monitoring disk space is as important as monitoring the security tools. A sensor going silent is a critical visibility gap — the absence of logs is not the absence of attacks.

---

## Lesson 2: OpenSearch Query Design Matters at Scale

### What Happened
Early dashboard versions used `match_all` queries with Python-side filtering. At 6M+ alerts this was impractical — each call pulled thousands of records, parsed them in Python, and timed out.

### Resolution
All aggregation was moved into OpenSearch. A single query with nested aggregations (timeline, by_country, by_src_ip, by_eventid, mitre) returns everything in one round trip in under 2 seconds:
```python
body = {
  "size": 0, "track_total_hits": True,
  "aggs": {
    "by_country": {"terms": {"field": "data.location.country_name", "size": 100}},
    "by_src_ip":  {"terms": {"field": "data.src_ip", "size": 2000}},
    "timeline":   {"date_histogram": {...}},
  }
}
```

### Takeaway
At millions of events, query design is the difference between a 2-second response and a 60-second timeout. Aggregations push computation to the data instead of pulling data to compute.

---

## Lesson 3: AI Models Have Real Hardware Constraints

### What Happened
`llama3.3:70b` produced better reasoning than `llama3.1:8b`, but the RTX 4070's 8GB VRAM couldn't hold it. Ollama offloaded ~42GB to system RAM and inference took 10–15 minutes instead of 15–30 seconds.

### Resolution
Reverted to `llama3.1:8b` (fits entirely in VRAM) and compensated with prompt engineering — feeding pre-aggregated statistics directly rather than asking the model to infer scale from a small sample.

### Takeaway
Consumer GPU hardware is a real constraint for local LLM deployment. A smaller model with well-structured inputs often beats a larger model with poorly structured ones.

---

## Lesson 4: Cowrie Accepts Everything — By Design

### What Happened
Credential data showed a 63.3% "success" rate, which seemed implausibly high.

### Resolution
Cowrie accepts all credentials by design — `cowrie.login.success` means "Cowrie let the attacker into the fake shell," not "valid credential." The value is in what attackers do *after* they log in.

### Takeaway
Understanding data requires understanding the tool that generates it. The 63.3% rate is an artifact, not a finding.

---

## Lesson 5: rsync + File Rotation Requires Careful Ordering

### What Happened
After the disk outage, the consolidation command initially missed data because the `cat` ordering didn't account for the logrotate `.1` suffix at day boundaries.

### Resolution
Consolidation explicitly includes all variants in chronological order (date-suffixed files, then `.1`, then current `cowrie.json`).

### Takeaway
Log rotation creates multiple file formats. Any consolidation pipeline must account for all of them; a missing file silently produces an incomplete dataset.

---

## Lesson 6: Canvas Rendering Requires Layout to Complete First

### What Happened
The Geographic Attack Map (HTML5 Canvas) rendered blank because `offsetWidth` returned 0 when queried before the browser finished layout.

### Resolution
Wrapped the draw code in staged `setTimeout` calls (0/200/500ms) so at least one execution runs after layout completes; later HiDPI scaling was added for crisp rendering on high-DPI displays.

### Takeaway
Browser rendering is asynchronous. JavaScript that measures DOM dimensions must wait for the layout phase (`requestAnimationFrame` / `setTimeout`).

---

## Lesson 7: Botnet Detection by Behavioral Signature

### What Happened
IP-based botnet clustering was unreliable because campaigns rotate IPs constantly.

### Resolution
Switched to behavioral signatures consistent across all IPs in a campaign: the `mdrfckr` SSH key string, the `345gs5662d34` credential, the Solana-only username set. Detection dedups on the **campaign type** (what the command does), not the first token — so a multi-stage implant that begins with `cd` is still classified as an SSH key implant rather than being shadowed by a generic `cd` command.

### Takeaway
Behavioral IOCs are more durable than network IOCs. Changing an IP is trivial; changing a payload or credential list requires retooling the whole campaign.

---

## Lesson 8: A Wrong Column Name Silently Dropped Every Malware Capture

### What Happened
The Dionaea honeypot was capturing real malware to disk (7 binaries, later confirmed as WannaCry), yet the dashboard reported **0 binaries captured** for days. Connections were logged; captures were not.

### Root Cause
`parse_dionaea.py` queried `SELECT connection, url, sha512 FROM downloads` — but the real Dionaea schema has **`download_url`** and **`download_md5_hash`**, with no `url` or `sha512` column. The query threw an exception, which was swallowed by a broad `except:` that fell back to an empty result — so every capture was silently discarded. The parser was also stuck on an unadvanced state cursor.

### Resolution
Rewrote the query against the verified schema, joined `downloads → connections` for source attribution, switched dedup to be hash-keyed (independent of the connection cursor), and **computed the real SHA256 from the captured file on disk** (falling back to MD5 only if the file isn't synced, so a capture is never dropped). A bytes-to-string sanitizer was added because Dionaea returns some TEXT columns as BLOBs, which broke JSON serialization. VirusTotal enrichment and a permanent read-only archive were layered on top. The whole pipeline was then automated with a systemd timer.

### Takeaway
A broad `except:` that hides the real error is dangerous — it turns a loud, fixable bug into silent data loss. Validate assumptions against the **actual** schema, not the documented or assumed one, and let parsing errors surface loudly. "No data" should be treated as suspicious until proven, especially when the upstream sensor clearly has data on disk.

---

## Lesson 9: Hardcoded Credentials, and Migrating to Environment Variables

### What Happened
During development, the OpenSearch admin password was hardcoded across five files (the dashboard, two triage scripts, a GeoIP rebuild script, and an IP-resolver script) — some with no environment fallback at all. Because several of these were committed, the credential ended up in the public git history.

### Resolution
All five files were migrated to read the password from the `OPENSEARCH_PASS` environment variable with no hardcoded fallback. The value is now supplied only at runtime: via the systemd unit override for the dashboard, and via environment lines in the relevant cron/crontab entries for the batch jobs. A pre-commit check (`git grep --cached` for the secret pattern) was adopted as a gate so a credential can never be staged again. Stale `__pycache__` `.pyc` files — which retained the secret after the source was cleaned — were purged as part of the scrub.

### Takeaway
Secrets do not belong in source, and they especially do not belong in git history (where a later deletion does not undo the exposure — only rotation does). Centralize secrets in the runtime environment, treat any exposed secret as compromised, and enforce a mechanical pre-commit gate rather than relying on memory. Compiled artifacts (`.pyc`) can retain a secret after the source is fixed, so they must be cleaned too.
