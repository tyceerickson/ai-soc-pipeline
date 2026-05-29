#!/usr/bin/env python3
"""
parse_dionaea.py — Dionaea SQLite parser for Wazuh ingestion
Project 4: AI-Powered SOC Pipeline · CMU MSISPM Portfolio · Tyce Erickson

Reads /opt/cowrie-logs/dionaea/dionaea.sqlite (synced from VPS every 15 min),
extracts structured connection/login/malware events, enriches with GeoIP,
writes /opt/cowrie-logs/wazuh/wazuh-dionaea.json for Wazuh agent pickup.

SQLite schema (verified against the live dionaea.sqlite):
  connections  - connection, connection_protocol, connection_timestamp,
                 local_port, remote_host, remote_port
  logins       - connection, login_username, login_password
  downloads    - connection, download_url, download_md5_hash   (NOTE: md5, not sha512)
  offers       - connection, offer_url                          (payload offered, may pre-date download)
  virustotals  - virustotal_md5_hash, virustotal_permalink      (Dionaea's own VT, if enabled)

Binary capture:
  Dionaea names each saved file in binaries/ by its MD5. We emit one
  'dionaea.binary.captured' event per distinct downloaded hash, attributed to the
  source IP via the downloads->connections join. If the binaries dir is synced to
  this host (BINARIES_DIR), we compute the real SHA256 from the file (verifiable,
  VirusTotal-ready); otherwise we fall back to the MD5 the DB recorded so a capture
  is never dropped for lack of the file.

VirusTotal:
  If VT_API_KEY is set, we look up each hash (hash only — the sample is NEVER
  uploaded) and attach the detection ratio + permalink. Results are cached in
  VT_CACHE so the same hash is queried at most once. Free-tier safe (rate-limited).

Run:
  python3 /opt/cowrie-tools/pipeline/parse_dionaea.py
  cron (existing): */15 * * * * terickson python3 .../parse_dionaea.py >> .../parse_dionaea.log 2>&1

Author: Tyce Erickson
"""

import json
import os
import sqlite3
import time
import fcntl
import hashlib
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

SQLITE_INPUT   = "/opt/cowrie-logs/dionaea/dionaea.sqlite"
OUTPUT_FILE    = "/opt/cowrie-logs/wazuh/wazuh-dionaea.json"
STATE_FILE     = "/opt/cowrie-logs/dionaea/.parse_state_sqlite.json"
GEOIP_CACHE    = "/opt/cowrie-logs/geoip_cache.json"
GEOIP_CITY_DB  = "/opt/geoip/GeoLite2-City.mmdb"
GEOIP_ASN_DB   = "/opt/geoip/GeoLite2-ASN.mmdb"
# Directory of captured binaries, synced from the VPS (filename == md5). Optional:
# if present we compute real SHA256 from the file; if not, we fall back to the md5.
BINARIES_DIR   = os.environ.get("DIONAEA_BINARIES_DIR", "/opt/cowrie-logs/dionaea/binaries")
VT_CACHE       = "/opt/cowrie-logs/dionaea/.vt_cache.json"
VT_API_KEY     = os.environ.get("VT_API_KEY", "").strip()
# Permanent malware archive: each new sample is copied here (organised by month,
# named by sha256) with a JSON metadata sidecar, so the sample + its context
# survive index rollover and container/binary-dir rotation.
ARCHIVE_DIR    = os.environ.get("DIONAEA_ARCHIVE_DIR", "/opt/cowrie-logs/dionaea/archive")
SENSOR         = "digitalocean-nyc1"
LOOKBACK_HOURS = 25

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("parse-dionaea-sqlite")

PORT_SERVICE = {
    21: "ftp", 445: "smb", 1433: "mssql", 3306: "mysql",
    80: "http", 443: "https", 4444: "shellcode", 5060: "sip",
    69: "tftp", 135: "msrpc", 139: "netbios",
}

def service_for_port(port):
    return PORT_SERVICE.get(int(port) if port else 0, f"port-{port}")

def _clean(v):
    """Make a value JSON-safe. Dionaea's SQLite sometimes returns TEXT columns as
    bytes/BLOB (e.g. download_url, remote_host); decode those to str. Recurses into
    dicts/lists so nested values (like the geo location dict) are covered too."""
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", "replace")
        except Exception:
            return v.hex()
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_clean(x) for x in v]
    return v

_geoip_cache = {}
_geoip_cache_ts = 0

def load_geoip_cache():
    global _geoip_cache, _geoip_cache_ts
    now = time.time()
    if now - _geoip_cache_ts < 60 and _geoip_cache:
        return _geoip_cache
    try:
        with open(GEOIP_CACHE) as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                _geoip_cache = json.load(f)
                _geoip_cache_ts = now
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except Exception:
        pass
    return _geoip_cache

def resolve_ip(ip):
    cache = load_geoip_cache()
    if ip in cache and cache[ip].get("country"):
        c = cache[ip]
        return {"country_name": c.get("country",""), "country_code": "",
                "city_name": c.get("city",""), "org": c.get("org",""), "asn": ""}
    try:
        import geoip2.database
        city_r = geoip2.database.Reader(GEOIP_CITY_DB)
        asn_r  = geoip2.database.Reader(GEOIP_ASN_DB)
        city   = city_r.city(ip)
        asn    = asn_r.asn(ip)
        result = {
            "country_name": city.country.name or "",
            "country_code": city.country.iso_code or "",
            "city_name":    city.city.name or "",
            "org":          asn.autonomous_system_organization or "",
            "asn":          f"AS{asn.autonomous_system_number}" if asn.autonomous_system_number else "",
        }
        city_r.close(); asn_r.close()
        cache[ip] = {"country": result["country_name"], "city": result["city_name"], "org": result["org"]}
        try:
            with open(GEOIP_CACHE, "w") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    json.dump(cache, f)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
        except Exception:
            pass
        return result
    except Exception:
        return {"country_name": "", "country_code": "", "city_name": "", "org": "", "asn": ""}

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"last_connection_id": 0, "seen_hashes": []}

def save_state(state):
    try:
        Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as e:
        log.warning("Could not save state: %s", e)

# ── VirusTotal cache + lookup (hash only; sample never uploaded) ────────────
def _load_vt_cache():
    try:
        with open(VT_CACHE) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_vt_cache(cache):
    try:
        Path(VT_CACHE).parent.mkdir(parents=True, exist_ok=True)
        with open(VT_CACHE, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass

def vt_lookup(hash_value, cache):
    """Look up a file hash on VirusTotal v3. Returns a small dict or None.
    Only the hash is transmitted — the binary is never uploaded."""
    if not VT_API_KEY or not hash_value:
        return None
    if hash_value in cache:
        return cache[hash_value]
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    req = urllib.request.Request(url, headers={"x-apikey": VT_API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
        attr = data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        result = {
            "vt_malicious":  stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_total":      sum(v for v in stats.values() if isinstance(v, int)),
            "vt_label":      (attr.get("popular_threat_classification", {}) or {}).get("suggested_threat_label", ""),
            "vt_type":       attr.get("type_description", ""),
            "vt_permalink":  f"https://www.virustotal.com/gui/file/{hash_value}",
            "vt_checked":    datetime.now(timezone.utc).isoformat(),
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result = {"vt_malicious": 0, "vt_total": 0, "vt_label": "",
                      "vt_permalink": f"https://www.virustotal.com/gui/file/{hash_value}",
                      "vt_unknown": True, "vt_checked": datetime.now(timezone.utc).isoformat()}
        elif e.code == 429:
            log.warning("VirusTotal rate limit hit — skipping remaining lookups this run")
            return None
        else:
            log.warning("VT lookup failed for %s: HTTP %s", hash_value[:12], e.code)
            return None
    except Exception as e:
        log.warning("VT lookup error for %s: %s", hash_value[:12], e)
        return None
    cache[hash_value] = result
    return result

def sha256_of(md5_name):
    """Compute SHA256 from the captured file (named by md5) if it's synced here."""
    path = os.path.join(BINARIES_DIR, md5_name)
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest(), os.path.getsize(path)
    except Exception:
        return None, None

def archive_binary(md5_name, event):
    """Copy a captured sample into the permanent archive, named by sha256 under a
    YYYY-MM folder, with a JSON metadata sidecar. Idempotent: skips if already
    archived. Returns the archive path or None. Never raises — archiving must not
    break event emission."""
    try:
        src = os.path.join(BINARIES_DIR, md5_name)
        if not os.path.exists(src):
            return None  # file not synced here; nothing to archive
        sha = event.get("sha256") or md5_name
        month = (event.get("timestamp", "") or datetime.now(timezone.utc).isoformat())[:7]  # YYYY-MM
        dest_dir = os.path.join(ARCHIVE_DIR, month)
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, sha)
        if not os.path.exists(dest):
            import shutil
            shutil.copy2(src, dest)
            try:
                os.chmod(dest, 0o400)  # read-only — it's malware; don't let it be run/edited
            except Exception:
                pass
        meta = {
            "sha256":     event.get("sha256", ""),
            "md5":        event.get("md5", ""),
            "file_size":  event.get("file_size", ""),
            "first_seen": event.get("timestamp", ""),
            "src_ip":     event.get("src_ip", ""),
            "country":    (event.get("location", {}) or {}).get("country_name", ""),
            "org":        (event.get("location", {}) or {}).get("org", ""),
            "service":    event.get("service", ""),
            "download_url": event.get("download_url", ""),
            "vt_malicious": event.get("vt_malicious", ""),
            "vt_total":     event.get("vt_total", ""),
            "vt_label":     event.get("vt_label", ""),
            "vt_permalink": event.get("vt_permalink", ""),
            "archived_at":  datetime.now(timezone.utc).isoformat(),
        }
        with open(dest + ".json", "w") as f:
            json.dump(meta, f, indent=2)
        return dest
    except Exception as e:
        log.warning("archive failed for %s: %s", md5_name[:12], e)
        return None

def main():
    if not os.path.exists(SQLITE_INPUT):
        log.warning("SQLite file not found: %s - waiting for first rsync", SQLITE_INPUT)
        return

    state     = load_state()
    state.setdefault("seen_hashes", [])
    cutoff_ts = int((datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)).timestamp())

    try:
        db = sqlite3.connect(f"file:{SQLITE_INPUT}?mode=ro", uri=True,
                             check_same_thread=False, timeout=10)
    except Exception as e:
        log.error("Could not open SQLite: %s", e)
        return

    events = []
    try:
        # ── Connections (and their logins) — incremental by connection id ────
        cur = db.execute("""
            SELECT connection, connection_type, connection_transport,
                   connection_protocol, connection_timestamp,
                   local_host, local_port, remote_host, remote_port
            FROM connections
            WHERE connection > ?
              AND connection_timestamp > ?
              AND remote_host IS NOT NULL
              AND remote_host NOT IN ('127.0.0.1', '::1', '')
            ORDER BY connection ASC
        """, (state.get("last_connection_id", 0), cutoff_ts))
        connections = cur.fetchall()

        conn_ids    = [r[0] for r in connections]
        max_conn_id = max(conn_ids) if conn_ids else state.get("last_connection_id", 0)

        login_map = {}
        if conn_ids:
            ph = ",".join("?" * len(conn_ids))
            cur = db.execute(
                f"SELECT connection, login_username, login_password FROM logins WHERE connection IN ({ph})",
                conn_ids)
            for row in cur.fetchall():
                login_map.setdefault(row[0], []).append((row[1], row[2]))

        for row in connections:
            try:
                (conn_id, conn_type, conn_transport, conn_protocol, conn_ts,
                 local_host, local_port, remote_host, remote_port) = row
                ts  = datetime.fromtimestamp(conn_ts, tz=timezone.utc).isoformat() if conn_ts else datetime.now(timezone.utc).isoformat()
                svc = conn_protocol or service_for_port(local_port)
                event = {
                    "timestamp":       ts,
                    "eventid":         f"dionaea.connection.{svc}",
                    "honeypot":        "dionaea",
                    "honeypot_type":   "malware_capture",
                    "honeypot_sensor": SENSOR,
                    "src_ip":          remote_host or "",
                    "src_port":        str(remote_port or ""),
                    "dst_port":        str(local_port or ""),
                    "service":         svc,
                    "connection_id":   conn_id,
                    "wazuh_rule_hint": 100200,
                    "wazuh_level":     3,
                }
                if conn_id in login_map:
                    logins = login_map[conn_id]
                    event["login_attempts"] = len(logins)
                    event["username"]       = logins[0][0] if logins else ""
                    event["password"]       = logins[0][1] if logins else ""
                    event["eventid"]        = f"dionaea.login.{svc}"
                    event["wazuh_level"]    = 6
                    event["wazuh_rule_hint"] = 100210
                if remote_host:
                    event["location"] = resolve_ip(remote_host)
                events.append(event)
            except Exception as e:
                log.warning("Error building connection event: %s", e)
                continue

        # ── Downloads (malware binaries) — keyed by HASH, not by the connection
        #    cursor, so a capture is never missed if its connection id was already
        #    processed. We emit each distinct md5 once (tracked in seen_hashes). ──
        vt_cache = _load_vt_cache()
        seen = set(state.get("seen_hashes", []))
        new_seen = []
        vt_calls = 0
        try:
            cur = db.execute("""
                SELECT d.download_md5_hash, d.download_url, c.remote_host,
                       c.remote_port, c.local_port, c.connection_protocol,
                       c.connection_timestamp
                FROM downloads d
                JOIN connections c ON d.connection = c.connection
                WHERE d.download_md5_hash IS NOT NULL AND d.download_md5_hash != ''
                ORDER BY c.connection_timestamp ASC
            """)
            dl_rows = cur.fetchall()
        except Exception as e:
            log.warning("downloads query failed: %s", e)
            dl_rows = []

        # Pull any VT results Dionaea recorded itself (table may be empty)
        dionaea_vt = {}
        try:
            for h, link in db.execute(
                    "SELECT virustotal_md5_hash, virustotal_permalink FROM virustotals"):
                if h:
                    dionaea_vt[h] = link
        except Exception:
            pass

        for (md5, url, remote_host, remote_port, local_port, proto, conn_ts) in dl_rows:
            if md5 in seen:
                continue
            seen.add(md5)
            new_seen.append(md5)
            ts  = datetime.fromtimestamp(conn_ts, tz=timezone.utc).isoformat() if conn_ts else datetime.now(timezone.utc).isoformat()
            svc = proto or service_for_port(local_port)
            sha256, fsize = sha256_of(md5)   # real hash if file is synced here
            ev = {
                "timestamp":       ts,
                "eventid":         "dionaea.binary.captured",
                "honeypot":        "dionaea",
                "honeypot_type":   "malware_capture",
                "honeypot_sensor": SENSOR,
                "src_ip":          remote_host or "",
                "src_port":        str(remote_port or ""),
                "dst_port":        str(local_port or ""),
                "service":         svc,
                "md5":             md5,
                # Dashboard queries data.sha256: use the real file hash when we have
                # it, otherwise fall back to md5 so the capture still surfaces.
                "sha256":          sha256 or md5,
                "hash_type":       "sha256" if sha256 else "md5",
                "file_size":       fsize if fsize is not None else "",
                "download_url":    url or "",
                "wazuh_rule_hint": 100230,
                "wazuh_level":     12,
            }
            if remote_host:
                ev["location"] = resolve_ip(remote_host)
            # VirusTotal: prefer external lookup (richer); fall back to Dionaea's link
            vt = None
            if VT_API_KEY and vt_calls < 200:
                vt = vt_lookup(sha256 or md5, vt_cache)
                vt_calls += 1
                time.sleep(16)  # free-tier: 4 lookups/min — be polite
            if vt:
                ev.update(vt)
            elif md5 in dionaea_vt:
                ev["vt_permalink"] = dionaea_vt[md5]
            # Permanent archive (sample + metadata sidecar) — after VT so the
            # sidecar captures the verdict. Best-effort; never blocks the event.
            arch = archive_binary(md5, ev)
            if arch:
                ev["archived"] = True
            events.append(ev)

        if new_seen:
            _save_vt_cache(vt_cache)

    except Exception as e:
        log.error("SQLite processing failed: %s", e)
        db.close()
        return
    finally:
        db.close()

    # ── Dedup + write ────────────────────────────────────────────────────────
    seen_keys = set()
    deduped = []
    for ev in events:
        ts_min = ev["timestamp"][:15]
        if ev.get("eventid") == "dionaea.binary.captured":
            key = ("binary", ev.get("md5", ""))   # one per captured hash
        else:
            key = (ev.get("src_ip",""), ev.get("service",""), ev.get("eventid",""), ts_min)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(ev)

    Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    # Append-mode would duplicate across runs; the dashboard reads the full file,
    # so we rewrite the current window each run (connections are incremental;
    # binaries are deduped by hash via seen_hashes state).
    with open(OUTPUT_FILE, "w") as out_f:
        for ev in deduped:
            out_f.write(json.dumps(_clean(ev)) + "\n")

    n_binaries = sum(1 for e in deduped if e.get("eventid") == "dionaea.binary.captured")
    save_state({
        "last_connection_id": max_conn_id,
        "seen_hashes": (state.get("seen_hashes", []) + new_seen)[-5000:],
        "last_run": datetime.now(timezone.utc).isoformat(),
    })
    log.info("Dionaea parser: %d connections, %d logins, %d NEW binaries (%d events written)",
             len(connections), len(login_map), len(new_seen), len(deduped))

if __name__ == "__main__":
    main()
