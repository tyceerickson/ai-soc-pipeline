#!/usr/bin/env python3
"""forward_cowrie.py — append new Cowrie events from the synced raw log into the
Wazuh feed file (wazuh-cowrie.json). Events are written as flat JSON so Wazuh's
JSON decoder extracts fields into data.eventid / data.input / data.src_ip etc.
directly — no nested data.data wrapper that causes OpenSearch keyword-mapping
conflicts. Tracks byte offset; resets on rotation."""
import os, json

RAW   = "/opt/cowrie-logs/cowrie.json"
FEED  = "/opt/cowrie-logs/wazuh/wazuh-cowrie.json"
STATE = "/opt/cowrie-logs/.forward_cowrie.state"
SENSOR = "digitalocean-nyc1"

def load_offset():
    try:
        with open(STATE) as f: return int(f.read().strip())
    except Exception: return 0

def save_offset(o):
    with open(STATE, "w") as f: f.write(str(o))

def main():
    if not os.path.exists(RAW): return
    size = os.path.getsize(RAW)
    off = load_offset()
    if off > size: off = 0
    if off == size: return
    new = 0
    with open(RAW, "r", errors="replace") as rf:
        rf.seek(off)
        lines = rf.readlines()
        end = rf.tell()
    with open(FEED, "a") as wf:
        for ln in lines:
            ln = ln.strip()
            if not ln: continue
            try:
                ev = json.loads(ln)
            except Exception:
                continue
            ev["honeypot"] = "cowrie"
            ev["honeypot_sensor"] = SENSOR
            # Wrap under "data" so Wazuh maps sub-fields to data.* (data.eventid,
            # data.src_ip, etc.) for rule matching. The ingest pipeline flattens
            # data.data back to data.* before OpenSearch indexes it.
            wf.write(json.dumps({"data": ev}) + "\n")
            new += 1
    save_offset(end)
    print(f"forwarded {new} new cowrie events (offset {off} -> {end})")

if __name__ == "__main__":
    main()
