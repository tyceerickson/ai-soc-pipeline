#!/usr/bin/env python3
"""
parse_dionaea.py — Dionaea SQLite parser for Wazuh ingestion
Project 4: AI-Powered SOC Pipeline · CMU MSISPM Portfolio · Tyce Erickson

Reads /opt/cowrie-logs/dionaea/dionaea.sqlite (synced from VPS every 15 min),
extracts structured connection/login/malware events, enriches with GeoIP,
writes /opt/cowrie-logs/wazuh/wazuh-dionaea.json for Wazuh agent pickup.

SQLite schema (key tables):
  connections  - every TCP connection (remote_host, local_port, connection_protocol)
  logins       - auth attempts (login_username, login_password)
  downloads    - malware binaries (url, sha512)

Run:
  python3 /opt/cowrie-tools/pipeline/parse_dionaea.py
  cron: */15 * * * * terickson ...

Author: Tyce Erickson
"""

import json
import os
import sqlite3
import time
import fcntl
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

SQLITE_INPUT   = "/opt/cowrie-logs/dionaea/dionaea.sqlite"
OUTPUT_FILE    = "/opt/cowrie-logs/wazuh/wazuh-dionaea.json"
STATE_FILE     = "/opt/cowrie-logs/dionaea/.parse_state_sqlite.json"
GEOIP_CACHE    = "/opt/cowrie-logs/geoip_cache.json"
GEOIP_CITY_DB  = "/opt/geoip/GeoLite2-City.mmdb"
GEOIP_ASN_DB   = "/opt/geoip/GeoLite2-ASN.mmdb"
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
        return {"last_connection_id": 0}

def save_state(state):
    try:
        Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as e:
        log.warning("Could not save state: %s", e)

def main():
    if not os.path.exists(SQLITE_INPUT):
        log.warning("SQLite file not found: %s - waiting for first rsync", SQLITE_INPUT)
        return

    state     = load_state()
    cutoff_ts = int((datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)).timestamp())

    try:
        db = sqlite3.connect(f"file:{SQLITE_INPUT}?mode=ro", uri=True,
                             check_same_thread=False, timeout=10)
    except Exception as e:
        log.error("Could not open SQLite: %s", e)
        return

    try:
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
        """, (state["last_connection_id"], cutoff_ts))
        connections = cur.fetchall()

        if not connections:
            log.info("No new connections since last run (last_id=%d)", state["last_connection_id"])
            db.close()
            return

        conn_ids     = [r[0] for r in connections]
        max_conn_id  = max(conn_ids)
        placeholders = ",".join("?" * len(conn_ids))

        cur = db.execute(
            f"SELECT connection, login_username, login_password FROM logins WHERE connection IN ({placeholders})",
            conn_ids)
        login_map = {}
        for row in cur.fetchall():
            login_map.setdefault(row[0], []).append((row[1], row[2]))

        try:
            cur = db.execute(
                f"SELECT connection, url, sha512 FROM downloads WHERE connection IN ({placeholders})",
                conn_ids)
            download_map = {}
            for row in cur.fetchall():
                download_map.setdefault(row[0], []).append({"url": row[1] or "", "sha512": row[2] or ""})
        except Exception:
            download_map = {}

    except Exception as e:
        log.error("SQLite query failed: %s", e)
        db.close()
        return
    finally:
        db.close()

    events = []
    for row in connections:
        try:
            (conn_id, conn_type, conn_transport, conn_protocol, conn_ts,
             local_host, local_port, remote_host, remote_port) = row

            ts  = datetime.fromtimestamp(conn_ts, tz=timezone.utc).isoformat() if conn_ts else datetime.now(timezone.utc).isoformat()
            svc = conn_protocol or service_for_port(local_port)
            eid = f"dionaea.connection.{svc}"
            lvl = 3
            hint = 100200

            event = {
                "timestamp":       ts,
                "eventid":         eid,
                "honeypot":        "dionaea",
                "honeypot_type":   "malware_capture",
                "honeypot_sensor": SENSOR,
                "src_ip":          remote_host or "",
                "src_port":        str(remote_port or ""),
                "dst_port":        str(local_port or ""),
                "service":         svc,
                "connection_id":   conn_id,
                "wazuh_rule_hint": hint,
                "wazuh_level":     lvl,
            }

            if conn_id in login_map:
                logins = login_map[conn_id]
                event["login_attempts"] = len(logins)
                event["username"]       = logins[0][0] if logins else ""
                event["password"]       = logins[0][1] if logins else ""
                event["eventid"]        = f"dionaea.login.{svc}"
                event["wazuh_level"]    = 6
                event["wazuh_rule_hint"] = 100210

            if conn_id in download_map:
                dl = download_map[conn_id][0]
                event["sha512"]          = dl.get("sha512","")
                event["download_url"]    = dl.get("url","")
                event["eventid"]         = "dionaea.binary.captured"
                event["wazuh_level"]     = 12
                event["wazuh_rule_hint"] = 100230

            if remote_host:
                event["location"] = resolve_ip(remote_host)

            events.append(event)

        except Exception as e:
            log.warning("Error building event for row: %s", e)
            continue

    seen = set()
    deduped = []
    for ev in events:
        ts_min = ev["timestamp"][:15]
        key    = (ev.get("src_ip",""), ev.get("service",""), ev.get("eventid",""), ts_min)
        if key not in seen:
            seen.add(key)
            deduped.append(ev)

    Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as out_f:
        for ev in deduped:
            out_f.write(json.dumps(ev) + "\n")

    save_state({"last_connection_id": max_conn_id, "last_run": datetime.now(timezone.utc).isoformat()})
    log.info("Dionaea SQLite parser: %d connections, %d with logins, %d with downloads, %d written",
             len(connections), len(login_map), len(download_map), len(deduped))

if __name__ == "__main__":
    main()
