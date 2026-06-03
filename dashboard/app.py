#!/usr/bin/env python3
"""
app.py — AI-Powered SOC Dashboard (v6)

Flask backend for the Wazuh/Cowrie SOC dashboard.
Serves 10 API endpoints backed by OpenSearch and an Ollama LLM.

Environment variables (all optional — fall back to dev defaults):
    OPENSEARCH_URL   https://localhost:9200
    OPENSEARCH_USER  admin
    OPENSEARCH_PASS  <password>
    OLLAMA_URL       http://100.72.171.104:11434/api/generate
    GEOIP_CACHE_PATH /opt/cowrie-logs/geoip_cache.json

Usage:
    python3 app.py                  # development
    gunicorn -w 2 app:app           # production

Author: Tyce Erickson · CMU MSISPM Portfolio · Project 4
"""

import json
import os
import re
import time
import glob
import fcntl
import sqlite3
import logging
import subprocess
import threading
import ssl
import base64
import urllib.request
import urllib.error
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple
from flask import Flask, jsonify, render_template, request, Response

# ── .env file support (optional) ─────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # pip install python-dotenv to enable .env support

# ── Logging setup ────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("soc-dashboard")

app = Flask(__name__)
try:
    from flask_cors import CORS
    CORS(app)
except ImportError:
    pass  # pip install flask-cors

# ── Startup validation ────────────────────────────────────────
if not os.environ.get("OPENSEARCH_PASS"):
    log.warning("OPENSEARCH_PASS not set via env — using hardcoded default (dev mode only)")

# ── Request timing middleware ─────────────────────────────────
@app.before_request
def _before():
    request._start_time = time.time()

@app.after_request
def _after(response):
    dur = (time.time() - getattr(request, "_start_time", time.time())) * 1000
    log.info("%s %s → %d (%.0fms)", request.method, request.path, response.status_code, dur)
    return response

# ============================================================
# Configuration
# ============================================================
# ── OpenSearch connection ─────────────────────────────────────
OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL",  "https://localhost:9200")
OS_USER        = os.environ.get("OPENSEARCH_USER", "admin")
OS_PASS        = os.environ.get("OPENSEARCH_PASS", "")
ALERT_INDEX    = os.environ.get("ALERT_INDEX",     "wazuh-alerts-4.x-*")

# ── File paths (all overridable via env) ──────────────────────
GEOIP_CACHE    = os.environ.get("GEOIP_CACHE_PATH",  "/opt/cowrie-logs/geoip_cache.json")
GEOIP_SOURCE   = os.environ.get("GEOIP_SOURCE",      "/opt/cowrie-logs/cowrie_enriched.json")
TRIAGE_REPORT  = os.environ.get("TRIAGE_REPORT",     "/opt/wazuh-soc/data/triage_report.json")
ALERTS_RAW     = os.environ.get("ALERTS_RAW",        "/opt/wazuh-soc/data/alerts_raw.json")
PYTHON         = os.environ.get("PYTHON_BIN",        "/usr/bin/python3")
ENRICH_SCRIPT  = os.environ.get("ENRICH_SCRIPT",     "/opt/cowrie-tools/pipeline/enrich_logs.py")
EXPORT_SCRIPT  = os.environ.get("EXPORT_SCRIPT",     "/opt/cowrie-tools/pipeline/export_to_wazuh.py")
POLLER_SCRIPT  = os.environ.get("POLLER_SCRIPT",     "/opt/wazuh-soc/triage/alert_poller.py")
TRIAGE_SCRIPT  = os.environ.get("TRIAGE_SCRIPT",     "/opt/wazuh-soc/triage/ai_triage.py")
LOG_DIR        = os.environ.get("LOG_DIR",           "/opt/wazuh-soc/logs")
OLLAMA_URL     = os.environ.get("OLLAMA_URL",        "http://100.72.171.104:11434/api/generate")
DIONAEA_WAZUH  = os.environ.get("DIONAEA_WAZUH",  "/opt/cowrie-logs/wazuh/wazuh-dionaea.json")
NGINX_WAZUH    = os.environ.get("NGINX_WAZUH",    "/opt/cowrie-logs/wazuh/wazuh-nginx.json")

# ── Incident-management persistence (SQLite) ──────────────────
CASES_DB     = os.environ.get("CASES_DB",     "/opt/wazuh-soc/data/cases.db")
SCHEMA_FILE  = os.environ.get("SCHEMA_FILE",  os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql"))

# ── Startup config validation ─────────────────────────────────
for _script in [ENRICH_SCRIPT, TRIAGE_SCRIPT]:
    if not Path(_script).exists():
        log.warning("Script not found: %s — some features may be unavailable", _script)
for _dir in [LOG_DIR, str(Path(TRIAGE_REPORT).parent), str(Path(CASES_DB).parent)]:
    try:
        Path(_dir).mkdir(parents=True, exist_ok=True)
    except Exception as _e:
        log.warning("Cannot create dir %s: %s", _dir, _e)

# ── Cases DB init ─────────────────────────────────────────────
_db_lock = threading.Lock()

def get_db() -> sqlite3.Connection:
    """Open a SQLite connection with row access by name and FK enforcement."""
    conn = sqlite3.connect(CASES_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db() -> None:
    """Apply schema.sql (idempotent). Logs a warning if the file is missing."""
    try:
        with open(SCHEMA_FILE, encoding="utf-8") as f:
            ddl = f.read()
        conn = get_db()
        try:
            conn.executescript(ddl)
            conn.commit()
        finally:
            conn.close()
        log.info("Cases DB ready at %s", CASES_DB)
    except FileNotFoundError:
        log.warning("schema.sql not found at %s — cases features disabled", SCHEMA_FILE)
    except Exception as e:
        log.warning("Cases DB init failed: %s", e)

def audit(conn: sqlite3.Connection, case_id, action: str, detail: str = "", actor: str = "analyst") -> None:
    """Append a row to the audit_log. Caller is responsible for commit."""
    conn.execute(
        "INSERT INTO audit_log (case_id, action, detail, actor) VALUES (?,?,?,?)",
        (case_id, action, detail, actor),
    )

init_db()

# ── Response playbooks (hardcoded reference checklists) ────────
PLAYBOOKS = {
    "ssh_brute_force": {
        "name": "SSH Brute Force",
        "trigger": "Repeated failed SSH logins / credential stuffing from one IP",
        "steps": [
            "Confirm the source IP and count failed vs. successful logins",
            "Check whether any login succeeded (possible compromise)",
            "Block the source IP at the firewall / OPNsense",
            "Review commands run in any successful session",
            "Rotate credentials for any targeted accounts",
            "Document indicators (IP, creds tried) in case notes",
        ],
    },
    "malware_download": {
        "name": "Malware / Payload Download",
        "trigger": "file_download event or Dionaea binary capture",
        "steps": [
            "Identify the downloaded file hash and source URL",
            "Submit hash to VirusTotal / threat intel",
            "Determine the delivery vector (which honeypot/service)",
            "Check for secondary download or C2 callbacks",
            "Preserve the sample for analysis",
            "Add IOCs (hash, URL, IP) to case notes",
        ],
    },
    "web_scanning": {
        "name": "Web Scanning / Exploitation",
        "trigger": "nginx honeypot path probing, exploit signatures",
        "steps": [
            "Identify scanned paths and any exploit attempts",
            "Determine the scanner fingerprint / user-agent",
            "Check for successful exploitation indicators",
            "Correlate IP across other honeypots (cross-honeypot view)",
            "Block scanner IP/range if persistent",
            "Note targeted CVEs / paths in case notes",
        ],
    },
    "credential_compromise": {
        "name": "Credential Compromise",
        "trigger": "Successful login with known/leaked credentials",
        "steps": [
            "Identify which credential pair succeeded",
            "Trace all sessions using that credential",
            "Inventory actions taken post-login",
            "Force password reset on affected accounts",
            "Check for persistence mechanisms / new accounts",
            "Record timeline in case notes",
        ],
    },
    "botnet_activity": {
        "name": "Botnet / Coordinated Campaign",
        "trigger": "Many IPs sharing identical TTPs / command patterns",
        "steps": [
            "Confirm the shared fingerprint across source IPs",
            "Enumerate participating IPs and geographies",
            "Identify the command/payload pattern",
            "Check for a common C2 endpoint",
            "Block the IP set; consider range-level blocks",
            "Summarize the campaign in case notes",
        ],
    },
}


SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE
AUTH_HEADER = "Basic " + base64.b64encode(
    f"{OS_USER}:{OS_PASS}".encode()
).decode()

# ── Simple in-process rate limiter ───────────────────────────
_rate_buckets: Dict[str, Dict] = defaultdict(lambda: {"count": 0, "reset": 0.0})
_rate_lock = threading.Lock()

def rate_limit(max_per_minute: int = 60):
    """Decorator: allow at most max_per_minute calls/min per endpoint (global, not per-IP)."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = fn.__name__
            now = time.time()
            with _rate_lock:
                bucket = _rate_buckets[key]
                if now > bucket["reset"]:
                    bucket["count"] = 0
                    bucket["reset"] = now + 60
                bucket["count"] += 1
                if bucket["count"] > max_per_minute:
                    log.warning("Rate limit hit on %s (%d/min)", key, bucket["count"])
                    return jsonify({"error": "Rate limit exceeded — try again in a moment"}), 429
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ── Simple result cache ──────────────────────────────────────
_result_cache: Dict[str, Dict] = {}
_cache_lock = threading.Lock()

def cached(ttl_seconds: int = 300):
    """Decorator: cache function result for ttl_seconds."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = f"{fn.__name__}:{args}:{sorted(kwargs.items())}"
            now = time.time()
            with _cache_lock:
                entry = _result_cache.get(key)
                if entry and now < entry["expires"]:
                    log.debug("Cache hit: %s", fn.__name__)
                    return entry["value"]
            result = fn(*args, **kwargs)
            with _cache_lock:
                _result_cache[key] = {"value": result, "expires": now + ttl_seconds}
            return result
        return wrapper
    return decorator

analysis_state = {
    "running": False, "progress": "", "step": 0,
    "total_steps": 4, "started_at": None, "error": None,
}
refresh_state = {
    "running": False, "progress": "", "started_at": None, "error": None,
}


# ============================================================
# OpenSearch helper
# ============================================================
def os_query(path: str, body: Optional[Dict] = None, retries: int = 2) -> Dict:
    """Execute an OpenSearch query with retry logic on transient failures.

    Args:
        path:    URL path, e.g. "/wazuh-alerts-4.x-*/_search"
        body:    JSON request body (None for GET)
        retries: Number of retries on connection errors

    Returns:
        Parsed JSON response dict, or {"error": message} on failure.
    """
    url     = f"{OPENSEARCH_URL}{path}"
    headers = {"Content-Type": "application/json", "Authorization": AUTH_HEADER}
    data    = json.dumps(body).encode() if body else None
    method  = "POST" if data else "GET"

    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=25) as r:
                result = json.loads(r.read().decode())
                # Validate OpenSearch response has expected structure
                if "error" in result and "status" in result:
                    log.warning("OpenSearch error: %s", result.get("error", {}).get("reason", "unknown"))
                return result
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                return {"error": "Authentication failed — check OPENSEARCH_PASS"}
            if e.code == 429:
                wait = float(e.headers.get("Retry-After", 1))
                time.sleep(wait)
                continue
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except (urllib.error.URLError, OSError) as e:
            if attempt < retries:
                wait = 0.5 * (attempt + 1)
                log.warning("OpenSearch connection error (attempt %d/%d), retrying in %.1fs: %s",
                            attempt + 1, retries + 1, wait, e)
                time.sleep(wait)
            else:
                log.error("OpenSearch unreachable after %d attempts: %s", retries + 1, e)
                return {"error": "OpenSearch unreachable"}
        except Exception as e:
            log.error("os_query unexpected error: %s", e)
            return {"error": "Query failed"}
    return {"error": "Query failed after retries"}


# ============================================================
# GeoIP lookup
# ============================================================
# Module-level GeoIP cache — reloaded at most once per minute
_geoip_cache = {}
_geoip_cache_loaded_at = 0

def build_geoip_lookup() -> Dict[str, Dict]:
    """Load GeoIP cache from disk, refreshing at most once per minute.

    Returns:
        Dict mapping IP string to {country, city, org} dicts.
    """
    global _geoip_cache, _geoip_cache_loaded_at
    now = time.time()
    if now - _geoip_cache_loaded_at < 60 and _geoip_cache:
        return _geoip_cache
    try:
        with open(GEOIP_CACHE) as f:
            # Use shared file lock so concurrent reads don't race with writes
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                _geoip_cache = json.load(f)
                _geoip_cache_loaded_at = now
                return _geoip_cache
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except FileNotFoundError:
        log.warning("GeoIP cache not found at %s", GEOIP_CACHE)
    except Exception as e:
        log.warning("GeoIP cache load failed: %s", e)
    return _geoip_cache or {}  # Return stale cache rather than empty dict


def resolve_missing_ips_async(ips_list):
    """Background thread: resolve any IPs not in the GeoIP cache."""
    import threading
    def _resolve():
        try:
            cache_path = "/opt/cowrie-logs/geoip_cache.json"
            try:
                with open(cache_path) as f:
                    cache = json.load(f)
            except Exception:
                cache = {}
            missing = [ip for ip in ips_list if ip not in cache]
            if not missing:
                return
            try:
                import geoip2.database
                city_db = "/opt/geoip/GeoLite2-City.mmdb"
                asn_db  = "/opt/geoip/GeoLite2-ASN.mmdb"
                city_reader = geoip2.database.Reader(city_db)
                asn_reader  = geoip2.database.Reader(asn_db)
                resolved = 0
                for ip in missing[:50]:  # resolve up to 50 at a time
                    try:
                        city = city_reader.city(ip)
                        asn  = asn_reader.asn(ip)
                        cache[ip] = {
                            "country": city.country.name or "",
                            "city":    city.city.name or "",
                            "org":     asn.autonomous_system_organization or "",
                        }
                        resolved += 1
                    except Exception:
                        cache[ip] = {"country": "", "city": "", "org": ""}
                city_reader.close()
                asn_reader.close()
                if resolved > 0:
                    with open(cache_path, 'w') as f:
                        json.dump(cache, f)
            except Exception:
                pass
        except Exception:
            pass
    threading.Thread(target=_resolve, daemon=True).start()
    lookup = {}
    try:
        with open(GEOIP_SOURCE, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                    ip = e.get("src_ip")
                    if ip and ip not in lookup and e.get("src_country"):
                        lookup[ip] = {
                            "country": e.get("src_country", ""),
                            "city":    e.get("src_city", ""),
                            "org":     e.get("src_org", ""),
                        }
                except Exception:
                    continue
    except Exception:
        pass
    return lookup


# ============================================================
# Enriched stats
# ============================================================
def get_enriched_stats(since_ms, since):
    body_creds = {
        "size": 0,
        "query": {
            "bool": {"filter": [
                {"range":  {"data.timestamp": {"gte": since.isoformat()}}},
                {"exists": {"field": "data.honeypot"}},
                {"exists": {"field": "data.username"}},
                {"exists": {"field": "data.password"}},
                {"bool": {"should": [
                    {"term": {"data.eventid": "cowrie.login.failed"}},
                    {"term": {"data.eventid": "cowrie.login.success"}},
                ], "minimum_should_match": 1}},
            ]}
        },
        "aggs": {
            "unique_creds": {
                "terms": {
                    "script": {
                        "lang": "painless",
                        "source": "doc['data.username'].size() > 0 && doc['data.password'].size() > 0 ? doc['data.username'].value + '/' + doc['data.password'].value : null"
                    },
                    "size": 100,
                    "order": {"_count": "desc"},
                    "min_doc_count": 1
                }
            }
        }
    }
    result  = os_query(f"/{ALERT_INDEX}/_search", body_creds)
    buckets = result.get("aggregations", {}).get("unique_creds", {}).get("buckets", [])
    creds   = {b["key"]: b["doc_count"] for b in buckets}

    body_cmds = {
        "size": 0,
        "query": {
            "bool": {"filter": [
                {"range": {"data.timestamp": {"gte": since.isoformat()}}},
                {"exists": {"field": "data.honeypot"}},
                {"term":  {"data.eventid": "cowrie.command.input"}},
            ]}
        },
        "aggs": {
            "unique_cmds": {
                "terms": {
                    "field": "data.input",
                    "size":  150,
                    "order": {"_count": "desc"},
                    "min_doc_count": 1,
                }
            }
        }
    }
    result  = os_query(f"/{ALERT_INDEX}/_search", body_cmds)
    buckets = result.get("aggregations", {}).get("unique_cmds", {}).get("buckets", [])
    cmds    = dict(sorted(
        {b["key"]: b["doc_count"] for b in buckets}.items(),
        key=lambda x: x[1], reverse=True
    ))

    junk_patterns = ['GET ', 'POST ', 'USER ', 'PASS ', 'Host:', 'Mozilla',
                     'Accept', 'Content-', 'HTTP/', '*1/', 'EHLO', 'HELO']
    clean_creds = {
        k: v for k, v in creds.items()
        if not any(p in k for p in junk_patterns) and len(k) < 100
    }

    top_creds = [
        {"cred": k, "count": v}
        for k, v in sorted(clean_creds.items(), key=lambda x: x[1], reverse=True)[:100]
    ]
    top_cmds = [
        {"cmd": k, "count": v}
        for k, v in sorted(cmds.items(), key=lambda x: x[1], reverse=True)[:150]
    ]

    return {
        "top_credentials": top_creds,
        "top_commands":    top_cmds,
    }


# ============================================================
# Live stats query
# ============================================================
def get_live_stats(minutes=60):
    since    = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    since_ms = int(since.timestamp() * 1000)

    if minutes <= 120:
        i_type, i_val, interval = "fixed_interval",    "5m",   "5m"
    elif minutes <= 360:
        i_type, i_val, interval = "fixed_interval",    "15m",  "15m"
    elif minutes <= 720:
        i_type, i_val, interval = "fixed_interval",    "30m",  "30m"
    elif minutes <= 1440:
        i_type, i_val, interval = "fixed_interval",    "1h",   "1h"
    elif minutes <= 4320:
        i_type, i_val, interval = "fixed_interval",    "2h",   "2h"
    elif minutes <= 10080:
        i_type, i_val, interval = "fixed_interval",    "6h",   "6h"
    elif minutes <= 43200:
        i_type, i_val, interval = "fixed_interval",    "12h",  "12h"
    else:
        i_type, i_val, interval = "calendar_interval", "day",  "1d"

    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {"filter": [
                {"range": {"data.timestamp": {"gte": since.isoformat()}}},
                {"exists": {"field": "data.honeypot"}},
            ]}
        },
        "aggs": {
            "severity_critical": {"filter": {"range": {"rule.level": {"gte": 15}}}},
            "severity_high":     {"filter": {"range": {"rule.level": {"gte": 12, "lt": 15}}}},
            "severity_medium":   {"filter": {"range": {"rule.level": {"gte": 7,  "lt": 12}}}},
            "severity_low":      {"filter": {"range": {"rule.level": {"gte": 0,  "lt": 7}}}},
            "timeline": {
                "date_histogram": dict(
                    [("field", "data.timestamp"),
                     (i_type, i_val),
                     ("min_doc_count", 0),
                     ("extended_bounds", {
                         "min": since.isoformat(),
                         "max": datetime.now(timezone.utc).isoformat(),
                     })]
                ),
                "aggs": {
                    "high":   {"filter": {"range": {"rule.level": {"gte": 12}}}},
                    "medium": {"filter": {"range": {"rule.level": {"gte": 7, "lt": 12}}}},
                    "low":    {"filter": {"range": {"rule.level": {"gte": 0, "lt": 7}}}},
                }
            },
            "by_country": {
                "terms": {"field": "data.location.country_name", "size": 100, "missing": "Unknown"}
            },
            "by_src_ip": {"terms": {"field": "data.src_ip", "size": 2000}},
            "by_eventid": {"terms": {"field": "data.eventid", "size": 50}},
            "mitre_tactics":    {"terms": {"field": "rule.mitre.tactic",    "size": 20}},
            "mitre_techniques": {"terms": {"field": "rule.mitre.technique", "size": 20}},
            "mitre_ids":        {"terms": {"field": "rule.mitre.id",        "size": 20}},
            "tactic_timeline": {
                "date_histogram": dict(
                    [("field", "data.timestamp"),
                     (i_type, i_val),
                     ("min_doc_count", 0),
                     ("extended_bounds", {
                         "min": since.isoformat(),
                         "max": datetime.now(timezone.utc).isoformat(),
                     })]
                ),
                "aggs": {
                    "by_tactic": {"terms": {"field": "rule.mitre.tactic", "size": 10}}
                }
            },
        }
    }

    result = os_query(f"/{ALERT_INDEX}/_search", body)
    if "error" in result:
        return {"error": result["error"]}

    hits = result.get("hits", {})
    aggs = result.get("aggregations", {})
    total = hits.get("total", {}).get("value", 0)

    severity = {
        "critical": aggs.get("severity_critical", {}).get("doc_count", 0),
        "high":     aggs.get("severity_high",     {}).get("doc_count", 0),
        "medium":   aggs.get("severity_medium",   {}).get("doc_count", 0),
        "low":      aggs.get("severity_low",      {}).get("doc_count", 0),
    }

    timeline = []
    for b in aggs.get("timeline", {}).get("buckets", []):
        timeline.append({
            "time":   b.get("key_as_string", ""),
            "ts":     b.get("key", 0),
            "total":  b.get("doc_count", 0),
            "high":   b.get("high",   {}).get("doc_count", 0),
            "medium": b.get("medium", {}).get("doc_count", 0),
            "low":    b.get("low",    {}).get("doc_count", 0),
        })

    event_types = {}
    for b in aggs.get("by_eventid", {}).get("buckets", []):
        k = b["key"].replace("cowrie.", "").replace(".", " ")
        event_types[k] = b["doc_count"]

    geo_lookup = build_geoip_lookup()
    top_ips = []
    for b in aggs.get("by_src_ip", {}).get("buckets", []):
        ip  = b["key"]
        geo = geo_lookup.get(ip, {})
        top_ips.append({
            "ip":      ip,
            "count":   b["doc_count"],
            "country": geo.get("country", "") if isinstance(geo, dict) else "",
            "org":     geo.get("org", "") if isinstance(geo, dict) else "",
        })

    # Async-resolve any IPs not yet in GeoIP cache
    uncached = [ip["ip"] for ip in top_ips if not ip.get("country")]
    if uncached:
        resolve_missing_ips_async(uncached)

    # Build country totals from GeoIP-enriched top_ips so cowrie events
    # (which lack data.location.country_name in the index) are included.
    # This aligns the Top Attacker Countries panel with the Geographic Map.
    countries = {}
    for ip_info in top_ips:
        c = ip_info.get("country", "")
        if c:
            countries[c] = countries.get(c, 0) + ip_info["count"]
    if not countries:
        for b in aggs.get("by_country", {}).get("buckets", []):
            k = b["key"]
            if k and k != "Unknown":
                countries[k] = b["doc_count"]

    mitre_tactics    = {b["key"]: b["doc_count"] for b in aggs.get("mitre_tactics",    {}).get("buckets", [])}
    mitre_techniques = {b["key"]: b["doc_count"] for b in aggs.get("mitre_techniques", {}).get("buckets", [])}
    mitre_ids        = {b["key"]: b["doc_count"] for b in aggs.get("mitre_ids",        {}).get("buckets", [])}

    tactic_timeline = []
    all_tactics = set()
    for b in aggs.get("tactic_timeline", {}).get("buckets", []):
        pt = {"time": b.get("key_as_string", ""), "ts": b.get("key", 0)}
        for tb in b.get("by_tactic", {}).get("buckets", []):
            pt[tb["key"]] = tb["doc_count"]
            all_tactics.add(tb["key"])
        tactic_timeline.append(pt)
    for pt in tactic_timeline:
        for t in all_tactics:
            pt.setdefault(t, 0)

    mitre_panel    = build_mitre_panel(minutes, since_ms, mitre_tactics, mitre_techniques, mitre_ids)
    enriched_stats = get_enriched_stats(since_ms, since)

    return {
        "total":            total,
        "severity":         severity,
        "countries":        countries,
        "event_types":      event_types,
        "top_ips":          top_ips,
        "timeline":         timeline,
        "timeline_interval":interval,
        "mitre_tactics":    mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "mitre_ids":        mitre_ids,
        "mitre_panel":      mitre_panel,
        "tactic_timeline":  tactic_timeline,
        "all_tactics":      sorted(list(all_tactics)),
        "enriched_stats":   enriched_stats,
        "window_minutes":   minutes,
        "as_of":            datetime.now(timezone.utc).isoformat(),
    }


@cached(ttl_seconds=300)  # Cache MITRE for 5 minutes
def build_mitre_panel(minutes: int, since_ms: int, tactics: Dict, techniques: Dict, ids: Dict) -> List:
    """Build the MITRE ATT&CK panel dynamically from live data.

    Discovers ALL tactics present in the data — not just a hardcoded 7.
    Queries real examples for each tactic from OpenSearch.
    """
    # Build tactic→technique-ids map dynamically from what's actually in the data
    # This means new tactics appear automatically when Wazuh rules tag them
    tactic_map: Dict[str, List[str]] = {}
    for tactic in tactics:
        # Find technique IDs associated with this tactic from the live index
        t_body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"data.timestamp": {"gte": datetime.fromtimestamp(since_ms/1000, tz=timezone.utc).isoformat()}}},
                {"exists": {"field": "data.honeypot"}},
                {"term": {"rule.mitre.tactic": tactic}},
            ]}},
            "aggs": {"ids": {"terms": {"field": "rule.mitre.id", "size": 20}}}
        }
        t_result = os_query(f"/{ALERT_INDEX}/_search", t_body)
        found_ids = [b["key"] for b in t_result.get("aggregations", {}).get("ids", {}).get("buckets", [])]
        tactic_map[tactic] = found_ids if found_ids else []

    panel = []
    for tactic, count in sorted(tactics.items(), key=lambda x: x[1], reverse=True):
        body = {
            "size": 8,
            "query": {
                "bool": {"filter": [
                    {"range": {"data.timestamp": {"gte": datetime.fromtimestamp(since_ms/1000, tz=timezone.utc).isoformat()}}},
                    {"exists": {"field": "data.honeypot"}},
                    {"term":  {"rule.mitre.tactic": tactic}},
                ]}
            },
            "sort": [{"rule.level": "desc"}, {"data.timestamp": "desc"}],
            "_source": ["timestamp", "rule.description", "rule.level",
                        "data.src_ip", "data.username", "data.password",
                        "data.command", "data.eventid", "rule.mitre"],
        }
        result = os_query(f"/{ALERT_INDEX}/_search", body)
        examples = []
        for h in result.get("hits", {}).get("hits", []):
            src  = h.get("_source", {})
            data = src.get("data", {})
            examples.append({
                "timestamp":   src.get("timestamp", ""),
                "description": src.get("rule", {}).get("description", ""),
                "level":       src.get("rule", {}).get("level", 0),
                "src_ip":      data.get("src_ip", ""),
                "username":    data.get("username", ""),
                "password":    data.get("password", ""),
                "command":     (data.get("command", "") or "")[:80],
                "eventid":     data.get("eventid", ""),
                "mitre_id":    src.get("rule", {}).get("mitre", {}).get("id", []),
                "technique":   src.get("rule", {}).get("mitre", {}).get("technique", []),
            })
        panel.append({
            "tactic":     tactic,
            "count":      count,
            "tactic_ids": tactic_map.get(tactic, []),
            "examples":   examples,
        })
    return panel


# ============================================================
# NEW API: Attack Chain Funnel
# ============================================================
def resolve_alert_ips():
    """Resolve all unique IPs from recent OpenSearch alerts into GeoIP cache."""
    cache_path = "/opt/cowrie-logs/geoip_cache.json"
    try:
        with open(cache_path) as f:
            cache = json.load(f)
    except Exception:
        cache = {}

    # Get all unique IPs from alerts
    body = {
        "size": 0,
        "query": {"exists": {"field": "data.honeypot"}},
        "aggs": {
            "all_ips": {"terms": {"field": "data.src_ip", "size": 5000}}
        }
    }
    result = os_query(f"/{ALERT_INDEX}/_search", body)
    buckets = result.get("aggregations", {}).get("all_ips", {}).get("buckets", [])
    all_ips = [b["key"] for b in buckets]

    missing = [ip for ip in all_ips if ip not in cache or not cache[ip].get("country")]
    if not missing:
        return len(cache), 0

    try:
        import geoip2.database, glob
        # Search common locations for MaxMind databases
        search_dirs = [
            "/opt/geoip",
            "/opt/cowrie-tools/pipeline",
            "/opt/cowrie-tools",
            "/opt/cowrie-logs",
            "/usr/share/GeoIP",
            "/var/lib/GeoIP",
        ]
        city_db = asn_db = None
        for d in search_dirs:
            c = glob.glob(f"{d}/GeoLite2-City*.mmdb")
            a = glob.glob(f"{d}/GeoLite2-ASN*.mmdb")
            if c: city_db = c[0]
            if a: asn_db  = a[0]
            if city_db and asn_db: break
        if not city_db or not asn_db:
            return len(cache), -1  # databases not found

        city_reader = geoip2.database.Reader(city_db)
        asn_reader  = geoip2.database.Reader(asn_db)
        resolved = 0
        for ip in missing:
            try:
                city = city_reader.city(ip)
                asn  = asn_reader.asn(ip)
                cache[ip] = {
                    "country": city.country.name or "",
                    "city":    city.city.name or "",
                    "org":     asn.autonomous_system_organization or "",
                }
                resolved += 1
            except Exception:
                cache[ip] = {"country": "", "city": "", "org": ""}
        city_reader.close()
        asn_reader.close()
        # Use exclusive file lock to prevent concurrent write corruption
        with open(GEOIP_CACHE, 'w') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                json.dump(cache, f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        log.info("GeoIP cache updated: %d IPs resolved, %d total", resolved, len(cache))
        return len(cache), resolved
    except Exception as e:
        return len(cache), -1


def get_attack_chain(minutes):
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    body = {
        "size": 0,
        "timeout": "20s",
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since.isoformat()}}},
            {"exists": {"field": "data.honeypot"}},
        ]}},
        "aggs": {
            "connect":      {"filter": {"term": {"data.eventid": "cowrie.session.connect"}}},
            "client_kex":   {"filter": {"term": {"data.eventid": "cowrie.client.kex"}}},
            "login_failed": {"filter": {"term": {"data.eventid": "cowrie.login.failed"}}},
            "login_success":{"filter": {"term": {"data.eventid": "cowrie.login.success"}}},
            "cmd_input":    {"filter": {"term": {"data.eventid": "cowrie.command.input"}}},
            "file_download":{"filter": {"term": {"data.eventid": "cowrie.session.file_download"}}},
            "file_upload":  {"filter": {"term": {"data.eventid": "cowrie.session.file_upload"}}},
        }
    }
    result = os_query(f"/{ALERT_INDEX}/_search", body)
    aggs = result.get("aggregations", {})
    return {
        "stages": [
            {"name": "Session Connect",    "count": aggs.get("connect",       {}).get("doc_count", 0), "color": "#A0E7E5"},
            {"name": "SSH Key Exchange",   "count": aggs.get("client_kex",    {}).get("doc_count", 0), "color": "#7BC9FF"},
            {"name": "Login Failed",       "count": aggs.get("login_failed",  {}).get("doc_count", 0), "color": "#9395D3"},
            {"name": "Login Success",      "count": aggs.get("login_success", {}).get("doc_count", 0), "color": "#9395D3"},
            {"name": "Command Executed",   "count": aggs.get("cmd_input",     {}).get("doc_count", 0), "color": "#B388EB"},
            {"name": "File Downloaded",    "count": aggs.get("file_download", {}).get("doc_count", 0), "color": "#DDA0DD"},
            {"name": "File Uploaded",      "count": aggs.get("file_upload",   {}).get("doc_count", 0), "color": "#FF7F71"},
        ]
    }


# ============================================================
# NEW API: Attack Velocity (rolling 5-min rate)
# ============================================================
def get_velocity():
    now = datetime.now(timezone.utc)
    since_5m  = (now - timedelta(minutes=5)).isoformat()
    since_1h  = (now - timedelta(minutes=60)).isoformat()
    since_24h = (now - timedelta(minutes=1440)).isoformat()
    body = {
        "size": 0,
        "query": {"exists": {"field": "data.honeypot"}},
        "aggs": {
            "last_5m":  {"filter": {"range": {"data.timestamp": {"gte": since_5m}}}},
            "last_1h":  {"filter": {"range": {"data.timestamp": {"gte": since_1h}}}},
            "last_24h": {"filter": {"range": {"data.timestamp": {"gte": since_24h}}}},
            "per_minute": {
                "date_histogram": {
                    "field": "data.timestamp",
                    "fixed_interval": "1m",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": since_5m, "max": now.isoformat()}
                }
            }
        }
    }
    result = os_query(f"/{ALERT_INDEX}/_search", body)
    aggs = result.get("aggregations", {})
    last_5m  = aggs.get("last_5m",  {}).get("doc_count", 0)
    last_1h  = aggs.get("last_1h",  {}).get("doc_count", 0)
    last_24h = aggs.get("last_24h", {}).get("doc_count", 0)
    per_min_buckets = aggs.get("per_minute", {}).get("buckets", [])
    per_min = [{"ts": b["key"], "count": b["doc_count"]} for b in per_min_buckets]
    return {
        "current_rate": round(last_5m / 5, 1),
        "hourly_avg":   round(last_1h / 60, 1),
        "daily_avg":    round(last_24h / 1440, 1),
        "per_minute":   per_min,
        "last_5m":      last_5m,
        "last_1h":      last_1h,
        "last_24h":     last_24h,
    }


# ============================================================
# NEW API: Heatmap (hour x day)
# ============================================================
def get_heatmap():
    since = datetime.now(timezone.utc) - timedelta(days=14)
    body = {
        "size": 2000,
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since.isoformat()}}},
            {"exists": {"field": "data.honeypot"}},
        ]}},
        "_source": ["data.timestamp"],
    }
    result = os_query(f"/{ALERT_INDEX}/_search", body)
    # Use agg instead for efficiency
    body2 = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since.isoformat()}}},
            {"exists": {"field": "data.honeypot"}},
        ]}},
        "aggs": {
            "by_hour": {
                "date_histogram": {
                    "field": "data.timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 0,
                    "extended_bounds": {
                        "min": since.isoformat(),
                        "max": datetime.now(timezone.utc).isoformat()
                    }
                }
            }
        }
    }
    result = os_query(f"/{ALERT_INDEX}/_search", body2)
    buckets = result.get("aggregations", {}).get("by_hour", {}).get("buckets", [])
    # Build [day_offset][hour] matrix
    cells = {}
    for b in buckets:
        ts = b["key"] / 1000
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        day_key  = dt.strftime("%Y-%m-%d")
        hour_key = dt.hour
        key = f"{day_key}:{hour_key}"
        cells[key] = b["doc_count"]

    # Get unique days sorted
    days = sorted(set(k.split(":")[0] for k in cells.keys()))
    # Build grid
    grid = []
    for day in days[-14:]:  # last 14 days
        row = {"day": day, "hours": []}
        for h in range(24):
            row["hours"].append(cells.get(f"{day}:{h}", 0))
        grid.append(row)

    return {"grid": grid, "days": days[-14:]}


# ============================================================
# NEW API: Sessions (kill chain per session)
# ============================================================
def get_sessions(minutes):
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    since_iso = since.isoformat()

    # ── Step 1: rank ATTACKER IPs (not raw sessions) by interesting activity ──
    # Ranking sessions directly by _count lets a single hyperactive attacker (one
    # IP running thousands of commands) monopolize every slot, collapsing the
    # panel to "1 attacker". Instead we first find the top distinct source IPs
    # that produced interesting events, then pull representative sessions per IP.
    interesting = {"bool": {"should": [
        {"term": {"data.eventid": "cowrie.login.success"}},
        {"term": {"data.eventid": "cowrie.command.input"}},
        {"term": {"data.eventid": "cowrie.session.file_download"}},
    ], "minimum_should_match": 1}}

    ip_body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since_iso}}},
            {"exists": {"field": "data.honeypot"}},
            {"exists": {"field": "data.session"}},
            {"exists": {"field": "data.src_ip"}},
            interesting,
        ]}},
        "aggs": {
            "top_ips": {
                "terms": {"field": "data.src_ip", "size": 60, "order": {"max_lvl": "desc"}},
                "aggs": {
                    "max_lvl":  {"max": {"field": "rule.level"}},
                    # a couple of representative sessions per IP (most active)
                    "sessions": {"terms": {"field": "data.session", "size": 3, "order": {"_count": "desc"}}},
                },
            }
        },
    }
    ip_result = os_query(f"/{ALERT_INDEX}/_search", ip_body)
    ip_buckets = ip_result.get("aggregations", {}).get("top_ips", {}).get("buckets", [])

    # Collect session IDs across the top IPs (cap so the follow-up query stays light)
    session_ids = []
    for b in ip_buckets:
        for sb in b.get("sessions", {}).get("buckets", []):
            session_ids.append(sb["key"])
    session_ids = session_ids[:120]

    if not session_ids:
        return {"sessions": []}

    # ── Step 2: fetch events for those sessions ──────────────────────────────
    body2 = {
        "size": 3000,
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since_iso}}},
            {"exists": {"field": "data.honeypot"}},
            {"terms": {"data.session": session_ids}},
        ]}},
        "sort": [{"data.timestamp": "asc"}],
        "_source": ["data.session", "data.eventid", "data.src_ip", "data.timestamp",
                    "data.username", "data.password", "data.input", "data.command",
                    "rule.level", "rule.description", "rule.mitre"],
    }
    result2 = os_query(f"/{ALERT_INDEX}/_search", body2)

    geo_lookup = build_geoip_lookup()
    sessions = {}
    for h in result2.get("hits", {}).get("hits", []):
        src  = h.get("_source", {})
        data = src.get("data", {})
        rule = src.get("rule", {})
        sid  = data.get("session", "unknown")
        if sid not in sessions:
            ip  = data.get("src_ip", "")
            geo = geo_lookup.get(ip, {})
            sessions[sid] = {
                "session": sid,
                "src_ip":  ip,
                "country": geo.get("country", "") if isinstance(geo, dict) else "",
                "org":     geo.get("org", "") if isinstance(geo, dict) else "",
                "events":  [],
                "max_level": 0,
            }
        sessions[sid]["events"].append({
            "ts":        data.get("timestamp", ""),
            "eventid":   data.get("eventid", ""),
            "username":  data.get("username", ""),
            "password":  data.get("password", ""),
            "command":   (data.get("input", "") or data.get("command", "") or "")[:100],
            "level":     rule.get("level", 0),
            "desc":      rule.get("description", ""),
            "mitre":     rule.get("mitre", {}).get("tactic", []),
        })
        sessions[sid]["max_level"] = max(sessions[sid]["max_level"], rule.get("level", 0))

    return {"sessions": sorted(sessions.values(), key=lambda s: s["max_level"], reverse=True)}


# ============================================================
# NEW API: Botnet fingerprints
# ============================================================
def _levenshtein(s1: str, s2: str) -> int:
    """Compute edit distance between two strings (for credential deduplication).

    Uses Wagner-Fischer DP algorithm, O(m*n) time and O(n) space.
    """
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[len(s2)]


def get_botnets(minutes):
    """
    Auto-detect botnet campaigns by clustering credential and command patterns.
    
    Algorithm:
    1. Find top credential pairs used by 3+ unique IPs (coordinated = botnet)
    2. Find top command signatures used by 3+ unique IPs
    3. Check for Telnet protocol activity
    4. Cluster by dominant pattern, name dynamically from the data
    5. Fetch timeline for each detected campaign
    """
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    since_iso = since.isoformat()
    now_iso = datetime.now(timezone.utc).isoformat()
    PALETTE = ["#5c3020","#7a8090","#8a5868","#6a8060","#9888a8","#a07040",
               "#7a98b0","#c4899a","#8a3030","#6a7858","#a08060","#7a6888"]

    campaigns = []

    # ── Step 1: Credential campaigns ─────────────────────────────────────
    # Find credential pairs used by many unique IPs — coordinated = botnet
    cred_body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since_iso}}},
            {"exists": {"field": "data.honeypot"}},
            {"exists": {"field": "data.username"}},
            {"exists": {"field": "data.password"}},
        ]}},
        "aggs": {
            "cred_pairs": {
                "terms": {
                    "script": {
                        "lang": "painless",
                        "source": "doc['data.username'].size()>0 && doc['data.password'].size()>0 ? doc['data.username'].value+':::'+doc['data.password'].value : null"
                    },
                    "size": 100,
                    "min_doc_count": 5,
                    "order": {"_count": "desc"}
                },
                "aggs": {
                    "unique_ips": {"cardinality": {"field": "data.src_ip"}}
                }
            }
        }
    }
    cred_result = os_query(f"/{ALERT_INDEX}/_search", cred_body)
    for b in cred_result.get("aggregations", {}).get("cred_pairs", {}).get("buckets", []):
        cred   = b["key"]
        count  = b["doc_count"]
        n_ips  = b.get("unique_ips", {}).get("value", 0)
        if n_ips < 3 or ":::" not in cred:
            continue
        user, pwd = cred.split(":::", 1)
        # Name the campaign from the credential. Prefer a distinctive, non-generic
        # username (e.g. the infamous "mdrfckr" Diicot/Mexals signature) so the
        # campaign keeps its recognisable identity instead of being named after a
        # generic numeric password.
        GENERIC_USERS = {"root", "admin", "user", "test", "guest", "ubuntu", "oracle", "pi"}
        if len(user) >= 4 and user.lower() not in GENERIC_USERS and not user.isdigit():
            name = f"{user[:20]} Campaign"
        elif len(pwd) > 4 and (pwd == user or any(c.isdigit() for c in pwd)):
            name = f"{pwd[:20]} Campaign"
        elif len(user) > 3 and user not in ("root", "admin", "user", "test"):
            name = f"{user[:20]} Scanner"
        else:
            name = f"{user}/{pwd[:12]} Brute Force"
        # Filter protocol noise and junk credentials
        JUNK_CRED_PATTERNS = [
            'HTTP/', 'GET ', 'POST ', 'Host:', 'Mozilla', 'Content-',
            'User-Agent', 'EHLO', 'HELO', 'AUTH', 'SMTP', 'IMAP',
        ]
        # Also filter credentials that are clearly protocol tokens
        if pwd.startswith('*') or pwd.startswith('$') or '\\x' in pwd:
            continue
        if not any(c.isalnum() for c in pwd):
            continue
        if any(p in pwd or p in user for p in JUNK_CRED_PATTERNS):
            continue
        if len(pwd) > 60 or len(user) > 40:
            continue
        # Deduplicate near-identical credential variants (e.g. "345gs5662d34"
        # vs "3245gs5662d34", edit distance 1). Kept deliberately CONSERVATIVE so
        # genuinely distinct campaigns (e.g. a "mdrfkr"-style password) are NOT
        # absorbed into an unrelated cluster. Set BOTNET_DEDUP=0 to disable entirely.
        is_dupe = False
        if os.environ.get("BOTNET_DEDUP", "1") != "0":
            for existing in campaigns:
                ev = existing.get("_sig_val", "")
                eu = existing.get("_sig_user", "")
                if not ev:
                    continue
                # Only merge when the SAME username is involved — different users
                # are different campaigns even if passwords look alike.
                if eu != user:
                    continue
                shorter = min(pwd, ev, key=len)
                longer  = max(pwd, ev, key=len)
                # Long shared prefix/containment (one is a typo-extension of the other)
                if len(shorter) >= 8 and shorter in longer:
                    is_dupe = True
                # Very small edit distance on longish passwords only
                elif len(pwd) >= 8 and len(ev) >= 8 and _levenshtein(pwd, ev) <= 1:
                    is_dupe = True
                if is_dupe:
                    if count > existing["count"]:
                        existing["count"] = count
                        existing["unique_ips"] = max(existing["unique_ips"], n_ips)
                    break
        if is_dupe:
            continue
        # Confidence: HIGH = 5+ IPs, MEDIUM = 3-4 IPs, LOW = 1-2 IPs
        confidence = "HIGH" if n_ips >= 5 else "MEDIUM" if n_ips >= 3 else "LOW"
        campaigns.append({
            "_sig_field": "data.password",
            "_sig_val":   pwd,
            "_sig_user":  user,
            "name":       name,
            "count":      count,
            "unique_ips": n_ips,
            "confidence": confidence,
            "auto":       True,
        })

    # ── Step 2: Command signature campaigns ──────────────────────────────
    cmd_body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since_iso}}},
            {"exists": {"field": "data.honeypot"}},
            {"term": {"data.eventid": "cowrie.command.input"}},
        ]}},
        "aggs": {
            "top_cmds": {
                "terms": {
                    "field": "data.input",
                    "size":  30,
                    "min_doc_count": 5,
                    "order": {"_count": "desc"}
                },
                "aggs": {
                    "unique_ips": {"cardinality": {"field": "data.src_ip"}}
                }
            }
        }
    }
    cmd_result = os_query(f"/{ALERT_INDEX}/_search", cmd_body)
    seen_cmd_names = set()
    for b in cmd_result.get("aggregations", {}).get("top_cmds", {}).get("buckets", []):
        cmd   = b["key"]
        count = b["doc_count"]
        n_ips = b.get("unique_ips", {}).get("value", 0)
        if n_ips < 3 or len(cmd) < 5:
            continue
        words = cmd.split()
        sig = words[0] if words else cmd[:20]
        # Name by what the command DOES (signature of the campaign), checked in
        # priority order so a multi-stage command (e.g. the mdrfckr SSH-key implant
        # that starts with `cd` but contains ssh-rsa/authorized_keys) is classified
        # by its payload, not its first word.
        if "ssh-rsa" in cmd or "authorized_keys" in cmd:
            name = "SSH Key Implant"
        elif "chattr" in cmd or "lockr" in cmd:
            name = "Anti-Forensic (chattr/lockr)"
        elif "wget" in cmd or "curl" in cmd or "tftp" in cmd:
            name = "Downloader Campaign"
        elif "busybox" in cmd:
            name = "BusyBox IoT Scanner"
        elif "chmod" in cmd and ("setup" in cmd or "+x" in cmd):
            name = "Dropper Campaign"
        elif "uname" in cmd or "cat /proc" in cmd or "lscpu" in cmd:
            name = "System Recon Campaign"
        else:
            name = f"{sig[:20]} Campaign"
        # Dedup on the CAMPAIGN NAME (not the first word) so distinct payloads that
        # happen to share a leading token (cd, sh, ...) don't shadow each other.
        if name in seen_cmd_names:
            continue
        # Filter out generic Linux commands that aren't a recognised campaign type
        GENERIC_CMDS = {
            'echo','cat','ls','rm','df','free','ps','id','pwd','env','top',
            'who','w','last','uptime','date','hostname','uname','whoami',
            'ifconfig','ip','netstat','ss','lscpu','lsblk','mount','find',
            'grep','awk','sed','head','tail','wc','sort','uniq','cut','tr',
            'crontab','which','whereis','history','export','set','alias',
            'cd','mkdir','touch','cp','mv','chmod','chown','ln','stat',
        }
        is_named = not name.endswith(f"{sig[:20]} Campaign")
        if sig.lower() in GENERIC_CMDS and not is_named:
            continue
        # Filter out HTTP/protocol noise
        if any(x in sig for x in ['Host:', 'GET ', 'POST ', 'HTTP/', 'User-Agent',
                                    'Content-', 'Accept', 'Mozilla', '174.138']):
            continue
        seen_cmd_names.add(name)
        # Avoid duplicating credential campaigns that already cover this
        if not any(c["name"] == name for c in campaigns):
            confidence = "HIGH" if n_ips >= 5 else "MEDIUM" if n_ips >= 3 else "LOW"
            campaigns.append({
                "_sig_field": "data.input",
                "_sig_val":   sig,
                "name":       name,
                "count":      count,
                "unique_ips": n_ips,
                "confidence": confidence,
                "auto":       True,
            })

    # ── Step 3: Telnet scanner ────────────────────────────────────────────
    telnet_body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since_iso}}},
            {"exists": {"field": "data.honeypot"}},
            {"term": {"data.protocol": "telnet"}},
        ]}},
        "aggs": {"unique_ips": {"cardinality": {"field": "data.src_ip"}}}
    }
    tel_r  = os_query(f"/{ALERT_INDEX}/_search", telnet_body)
    tel_ct = tel_r.get("hits", {}).get("total", {}).get("value", 0)
    tel_ip = tel_r.get("aggregations", {}).get("unique_ips", {}).get("value", 0)
    if tel_ct > 0:
        campaigns.append({
            "_sig_field": "data.protocol",
            "_sig_val":   "telnet",
            "name":       "Telnet Scanner",
            "count":      tel_ct,
            "unique_ips": tel_ip,
            "auto":       True,
        })

    # ── Step 4: Deduplicate and limit to top 12 ───────────────────────────
    # Sort by count desc, deduplicate by name
    seen_names = set()
    deduped = []
    for c in sorted(campaigns, key=lambda x: x["count"], reverse=True):
        if c["name"] not in seen_names:
            seen_names.add(c["name"])
            deduped.append(c)
        if len(deduped) >= 50:
            break

    # ── Step 5: Fetch timelines IN PARALLEL ──────────────────────────────
    def fetch_timeline(args):
        i, camp = args
        field = camp["_sig_field"]
        sig   = camp["_sig_val"]
        if field == "data.protocol":
            q = {"term": {"data.protocol": sig}}
        elif field == "data.input":
            q = {"wildcard": {"data.input": f"*{sig}*"}}
        else:
            q = {"term": {field: sig}}
            if camp.get("_sig_user") and camp["_sig_user"] not in ("root","admin","user"):
                q = {"bool": {"must": [
                    {"term": {"data.password": sig}},
                    {"term": {"data.username": camp.get("_sig_user","")}},
                ]}}
        tl_body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"data.timestamp": {"gte": since_iso}}},
                {"exists": {"field": "data.honeypot"}},
                q,
            ]}},
            "aggs": {"timeline": {"date_histogram": {
                "field": "data.timestamp",
                "fixed_interval": "2h",
                "min_doc_count": 0,
                "extended_bounds": {"min": since_iso, "max": now_iso}
            }}}
        }
        tl_r = os_query(f"/{ALERT_INDEX}/_search", tl_body)
        tl   = [{"ts": b["key"], "count": b["doc_count"]}
                for b in tl_r.get("aggregations", {}).get("timeline", {}).get("buckets", [])]
        return i, camp, tl

    results_map = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        # Submit all, preserving order via index
        future_list = [(i, ex.submit(fetch_timeline, (i, camp))) for i, camp in enumerate(deduped)]
        for i, fut in future_list:
            try:
                idx, camp, tl = fut.result(timeout=10)
                results_map[idx] = (camp, tl)
            except Exception:
                # On failure, use empty timeline
                results_map[i] = (deduped[i], [])

    results = []
    for i, camp in enumerate(deduped):
        field = camp["_sig_field"]
        sig   = camp["_sig_val"]
        # Timeline already fetched in parallel above
        _, tl = results_map.get(i, (camp, []))

        results.append({
            "name":       camp["name"],
            "color":      PALETTE[i % len(PALETTE)],
            "count":      camp["count"],
            "unique_ips": camp["unique_ips"],
            "timeline":   tl,
            "auto":       True,
        })

    return {"botnets": results}


# ============================================================
# NEW API: Credential intelligence
# ============================================================
def get_credential_intel(minutes):
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    # New credentials (first seen in window)
    # Top credentials with success rate
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since.isoformat()}}},
            {"exists": {"field": "data.honeypot"}},
            {"exists": {"field": "data.username"}},
            {"exists": {"field": "data.password"}},
        ]}},
        "aggs": {
            "cred_combos": {
                "terms": {
                    "script": {
                        "lang": "painless",
                        "source": "doc['data.username'].size() > 0 && doc['data.password'].size() > 0 ? doc['data.username'].value + '/' + doc['data.password'].value : null"
                    },
                    "size": 30,
                    "order": {"_count": "desc"},
                    "min_doc_count": 1
                },
                "aggs": {
                    "successes": {"filter": {"term": {"data.eventid": "cowrie.login.success"}}},
                    "unique_ips": {"cardinality": {"field": "data.src_ip"}},
                }
            },
            "total_attempts": {"filter": {"term": {"data.eventid": "cowrie.login.failed"}}},
            "total_successes":{"filter": {"term": {"data.eventid": "cowrie.login.success"}}},
            "unique_creds":   {"cardinality": {
                "script": {
                    "lang": "painless",
                    "source": "doc['data.username'].size() > 0 && doc['data.password'].size() > 0 ? doc['data.username'].value + '/' + doc['data.password'].value : null"
                }
            }},
        }
    }
    result = os_query(f"/{ALERT_INDEX}/_search", body)
    aggs = result.get("aggregations", {})

    creds = []
    junk = ['GET ', 'POST ', 'HTTP/', 'USER ', 'Mozilla']
    for b in aggs.get("cred_combos", {}).get("buckets", []):
        key = b["key"]
        if any(p in key for p in junk) or len(key) > 100:
            continue
        successes  = b.get("successes", {}).get("doc_count", 0)
        total      = b.get("doc_count", 1)
        unique_ips = b.get("unique_ips", {}).get("value", 0)
        creds.append({
            "cred":        key,
            "count":       total,
            "successes":   successes,
            "success_pct": round(successes / total * 100, 1),
            "unique_ips":  unique_ips,
            "coordinated": unique_ips > 3,
        })

    return {
        "top_creds":       creds,
        "total_attempts":  aggs.get("total_attempts",  {}).get("doc_count", 0),
        "total_successes": aggs.get("total_successes", {}).get("doc_count", 0),
        "unique_creds":    aggs.get("unique_creds",    {}).get("value", 0),
    }

def get_dionaea_stats(minutes: int = 10080) -> dict:
    """Query OpenSearch for Dionaea malware honeypot stats.

    Returns service breakdown, top attacker IPs (with GeoIP),
    malware binaries captured, exploit incidents, and activity timeline.
    """
    since     = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    since_iso = since.isoformat()
    now_iso   = datetime.now(timezone.utc).isoformat()

    # Interval for timeline
    if minutes <= 1440:
        i_type, i_val = "fixed_interval",    "1h"
    elif minutes <= 10080:
        i_type, i_val = "fixed_interval",    "6h"
    else:
        i_type, i_val = "calendar_interval", "day"

    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {"filter": [
                {"range":  {"@timestamp": {"gte": since_iso}}},
                {"term":   {"data.honeypot":   "dionaea"}},
            ]}
        },
        "aggs": {
            # Total unique IPs
            "unique_ips": {"cardinality": {"field": "data.src_ip"}},
            # Service breakdown
            "by_service": {
                "terms": {"field": "data.service", "size": 20, "missing": "unknown"}
            },
            # Top attacker IPs
            "top_src_ips": {
                "terms": {"field": "data.src_ip", "size": 50}
            },
            # Event type breakdown
            "by_eventid": {
                "terms": {"field": "data.eventid", "size": 30}
            },
            # Binaries captured — pull one representative full doc per hash so we
            # get sha256, md5, file_size, src_ip, country, service + VirusTotal verdict
            "binaries": {
                "filter": {"term": {"data.eventid": "dionaea.binary.captured"}},
                "aggs": {
                    "hashes": {
                        "terms": {"field": "data.sha256", "size": 50},
                        "aggs": {
                            "sources": {"cardinality": {"field": "data.src_ip"}},
                            # Newest doc overall (for metadata even on non-VT samples)
                            "doc": {"top_hits": {
                                "size": 1,
                                "sort": [{"data.timestamp": "desc"}],
                                "_source": ["data.sha256", "data.md5", "data.file_size",
                                            "data.src_ip", "data.service", "data.download_url",
                                            "data.timestamp", "data.location.country_name",
                                            "data.vt_malicious", "data.vt_total", "data.vt_label",
                                            "data.vt_permalink", "data.vt_type"]
                            }},
                            # The most-recent event that ACTUALLY HAS a VT verdict —
                            # found even if it's old/buried, so re-emitted non-VT
                            # events never hide an existing verdict.
                            "vt_doc": {
                                "filter": {"exists": {"field": "data.vt_total"}},
                                "aggs": {
                                    "hit": {"top_hits": {
                                        "size": 1,
                                        "sort": [{"data.timestamp": "desc"}],
                                        "_source": ["data.vt_malicious", "data.vt_total",
                                                    "data.vt_label", "data.vt_permalink",
                                                    "data.vt_type", "data.md5", "data.file_size",
                                                    "data.src_ip", "data.service",
                                                    "data.location.country_name", "data.timestamp"]
                                    }}
                                }
                            },
                        }
                    },
                }
            },
            # Exploit incidents
            "incidents": {
                "filter": {"prefix": {"data.eventid": "dionaea.incident."}},
                "aggs": {
                    "by_type": {"terms": {"field": "data.incident_type", "size": 20}},
                    "by_ip":   {"terms": {"field": "data.src_ip", "size": 10}},
                }
            },
            # SMB auth attempts
            "smb_logins": {
                "filter": {"term": {"data.eventid": "dionaea.login.smb"}},
                "aggs": {
                    "by_ip": {"terms": {"field": "data.src_ip", "size": 10}},
                    "by_user": {"terms": {"field": "data.username", "size": 10}},
                }
            },
            # FTP auth attempts
            "ftp_logins": {
                "filter": {"term": {"data.eventid": "dionaea.login.ftp"}},
                "aggs": {
                    "by_ip": {"terms": {"field": "data.src_ip", "size": 10}},
                    "by_user": {"terms": {"field": "data.username", "size": 10}},
                }
            },
            # Activity timeline
            "timeline": {
                "date_histogram": dict(
                    [("field", "@timestamp"),
                     (i_type, i_val),
                     ("min_doc_count", 0),
                     ("extended_bounds", {"min": since_iso, "max": now_iso})]
                ),
                "aggs": {
                    "by_service": {"terms": {"field": "data.service", "size": 6}}
                }
            },
        }
    }

    result = os_query(f"/{ALERT_INDEX}/_search", body)
    if "error" in result:
        return {"error": result["error"]}

    hits = result.get("hits", {})
    aggs = result.get("aggregations", {})
    total = hits.get("total", {}).get("value", 0)

    geo_lookup = build_geoip_lookup()

    # Service breakdown
    services = {}
    for b in aggs.get("by_service", {}).get("buckets", []):
        services[b["key"]] = b["doc_count"]

    # Top IPs with GeoIP
    top_ips = []
    for b in aggs.get("top_src_ips", {}).get("buckets", []):
        ip  = b["key"]
        geo = geo_lookup.get(ip, {})
        top_ips.append({
            "ip":      ip,
            "count":   b["doc_count"],
            "country": geo.get("country", "") if isinstance(geo, dict) else "",
            "org":     geo.get("org", "") if isinstance(geo, dict) else "",
        })

    # Resolve any uncached IPs async
    uncached = [x["ip"] for x in top_ips if not x.get("country")]
    if uncached:
        resolve_missing_ips_async(uncached)

    # Malware binaries — full metadata + VirusTotal verdict per unique hash
    def _num(v):
        """Coerce VT counts to int — they may be stored as strings in the index."""
        if isinstance(v, bool):
            return None
        if isinstance(v, (int, float)):
            return int(v)
        if isinstance(v, str) and v.strip().lstrip("-").isdigit():
            return int(v.strip())
        return None

    binaries = []
    vt_known = 0
    for b in aggs.get("binaries", {}).get("hashes", {}).get("buckets", []):
        hits_ = b.get("doc", {}).get("hits", {}).get("hits", [])
        data  = (hits_[0].get("_source", {}).get("data", {}) if hits_ else {})
        # Overlay VT verdict from the dedicated vt_doc sub-agg (the most recent
        # event that actually carries VT), so a re-emitted non-VT event never
        # hides an existing verdict.
        vt_hits = b.get("vt_doc", {}).get("hit", {}).get("hits", {}).get("hits", [])
        if vt_hits:
            vt_data = vt_hits[0].get("_source", {}).get("data", {})
            for k, v in vt_data.items():
                if k not in data or not data.get(k):
                    data[k] = v
            # VT fields always come from vt_data
            for k in ("vt_malicious", "vt_total", "vt_label", "vt_permalink", "vt_type"):
                if k in vt_data:
                    data[k] = vt_data[k]
        loc   = data.get("location", {}) if isinstance(data.get("location"), dict) else {}
        vt_mal = _num(data.get("vt_malicious"))
        vt_tot = _num(data.get("vt_total"))
        if vt_tot is not None:
            vt_known += 1
        binaries.append({
            "sha256":       b["key"],
            "sha256_short": b["key"][:16] + "…",
            "count":        b["doc_count"],
            "unique_ips":   b.get("sources", {}).get("value", 0),
            "md5":          data.get("md5", ""),
            "file_size":    data.get("file_size", ""),
            "src_ip":       data.get("src_ip", ""),
            "country":      loc.get("country_name", "") or data.get("location", {}).get("country_name", "") if isinstance(data.get("location"), dict) else "",
            "service":      data.get("service", ""),
            "download_url": data.get("download_url", ""),
            "first_seen":   data.get("timestamp", ""),
            "vt_malicious": vt_mal,
            "vt_total":     vt_tot,
            "vt_label":     data.get("vt_label", ""),
            "vt_type":      data.get("vt_type", ""),
            "vt_permalink": data.get("vt_permalink", ""),
        })
    # Sort: most-flagged malware first, then by hit count
    binaries.sort(key=lambda x: (x["vt_malicious"] if isinstance(x["vt_malicious"], int) else -1, x["count"]), reverse=True)

    # Exploit incidents
    incident_types = {}
    for b in aggs.get("incidents", {}).get("by_type", {}).get("buckets", []):
        incident_types[b["key"]] = b["doc_count"]
    incident_ips = []
    for b in aggs.get("incidents", {}).get("by_ip", {}).get("buckets", []):
        ip  = b["key"]
        geo = geo_lookup.get(ip, {})
        incident_ips.append({
            "ip":      ip,
            "count":   b["doc_count"],
            "country": geo.get("country", "") if isinstance(geo, dict) else "",
        })

    # Login intelligence
    smb_users = [b["key"] for b in aggs.get("smb_logins", {}).get("by_user", {}).get("buckets", [])]
    ftp_users = [b["key"] for b in aggs.get("ftp_logins", {}).get("by_user", {}).get("buckets", [])]
    smb_count = aggs.get("smb_logins", {}).get("doc_count", 0)
    ftp_count = aggs.get("ftp_logins", {}).get("doc_count", 0)

    # Timeline — service-broken
    timeline = []
    all_services = set()
    for b in aggs.get("timeline", {}).get("buckets", []):
        pt = {"ts": b["key"], "time": b.get("key_as_string", ""), "total": b["doc_count"]}
        for sb in b.get("by_service", {}).get("buckets", []):
            pt[sb["key"]] = sb["doc_count"]
            all_services.add(sb["key"])
        timeline.append(pt)
    for pt in timeline:
        for svc in all_services:
            pt.setdefault(svc, 0)

    return {
        "total":           total,
        "unique_ips":      aggs.get("unique_ips", {}).get("value", 0),
        "services":        services,
        "top_ips":         top_ips,
        "binaries":        binaries,
        "binary_count":    aggs.get("binaries", {}).get("doc_count", 0),
        "unique_binaries": len(binaries),
        "vt_known_count":  vt_known,
        "incident_types":  incident_types,
        "incident_ips":    incident_ips,
        "smb_logins":      smb_count,
        "ftp_logins":      ftp_count,
        "smb_users":       smb_users[:10],
        "ftp_users":       ftp_users[:10],
        "timeline":        timeline,
        "all_services":    sorted(list(all_services)),
        "window_minutes":  minutes,
        "as_of":           datetime.now(timezone.utc).isoformat(),
    }

def get_nginx_stats(minutes: int = 10080) -> dict:
    """Query OpenSearch for nginx web honeypot stats.

    Returns top paths, HTTP methods, response codes, scanner types,
    user agent fingerprints, and request timeline.
    """
    since     = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    since_iso = since.isoformat()
    now_iso   = datetime.now(timezone.utc).isoformat()

    if minutes <= 1440:
        i_type, i_val = "fixed_interval",    "1h"
    elif minutes <= 10080:
        i_type, i_val = "fixed_interval",    "6h"
    else:
        i_type, i_val = "calendar_interval", "day"

    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            # Use @timestamp (Wazuh's indexed date field) — data.timestamp is stored
            # as a keyword string so range queries on it fail silently
            "bool": {"filter": [
                {"range": {"@timestamp": {"gte": since_iso}}},
                {"term":  {"data.honeypot": "nginx"}},
            ]}
        },
        "aggs": {
            "unique_ips":    {"cardinality": {"field": "data.src_ip"}},
            "unique_paths":  {"cardinality": {"field": "data.http_path"}},
            # HTTP method breakdown — stored as keyword, terms agg works fine
            "by_method": {
                "terms": {"field": "data.http_method", "size": 10, "missing": "UNKNOWN"}
            },
            # Response code — stored as keyword string ("404"), use terms not range
            "by_status": {
                "terms": {"field": "data.http_status", "size": 15}
            },
            # Top requested paths
            "top_paths": {
                "terms": {"field": "data.http_path", "size": 30}
            },
            # Path category breakdown
            "by_path_cat": {
                "terms": {"field": "data.path_category", "size": 20}
            },
            # Scanner type breakdown
            "by_scanner": {
                "terms": {"field": "data.scanner_type", "size": 20}
            },
            # Top source IPs
            "top_src_ips": {
                "terms": {"field": "data.src_ip", "size": 50}
            },
            # Top user agents
            "top_ua": {
                "terms": {"field": "data.user_agent", "size": 20}
            },
            # High-severity probes — rule.level IS numeric, range works
            "high_severity_probes": {
                "filter": {"range": {"rule.level": {"gte": 7}}},
                "aggs": {
                    "by_ip":   {"terms": {"field": "data.src_ip",   "size": 10}},
                    "by_path": {"terms": {"field": "data.http_path", "size": 10}},
                }
            },
            # Timeline — use @timestamp for date_histogram, NOT data.timestamp
            "timeline": {
                "date_histogram": dict(
                    [("field", "@timestamp"),
                     (i_type, i_val),
                     ("min_doc_count", 0),
                     ("extended_bounds", {"min": since_iso, "max": now_iso})]
                ),
                # Status class via terms on string field — map in Python after
                "aggs": {
                    "by_eventid": {
                        "terms": {"field": "data.eventid", "size": 10}
                    }
                }
            },
        }
    }

    result = os_query(f"/{ALERT_INDEX}/_search", body)
    if "error" in result:
        return {"error": result["error"]}

    hits = result.get("hits", {})
    aggs = result.get("aggregations", {})
    total = hits.get("total", {}).get("value", 0)

    geo_lookup = build_geoip_lookup()

    # HTTP methods
    methods = {}
    for b in aggs.get("by_method", {}).get("buckets", []):
        k = b["key"]
        # Filter out binary/protocol noise — only standard HTTP methods
        if re.match(r'^[A-Z]{2,8}$', k):
            methods[k] = b["doc_count"]

    # Response codes
    status_codes = {}
    for b in aggs.get("by_status", {}).get("buckets", []):
        status_codes[str(b["key"])] = b["doc_count"]

    # Top paths — clean up binary garbage
    top_paths = []
    for b in aggs.get("top_paths", {}).get("buckets", []):
        path = b["key"]
        # Skip binary/non-printable paths
        if not all(32 <= ord(c) <= 126 for c in path[:50]):
            continue
        top_paths.append({"path": path[:200], "count": b["doc_count"]})

    # Path categories
    path_cats = {b["key"]: b["doc_count"] for b in aggs.get("by_path_cat", {}).get("buckets", [])}

    # Scanner types
    scanners = {}
    for b in aggs.get("by_scanner", {}).get("buckets", []):
        scanners[b["key"]] = b["doc_count"]

    # Top IPs with GeoIP
    top_ips = []
    for b in aggs.get("top_src_ips", {}).get("buckets", []):
        ip  = b["key"]
        geo = geo_lookup.get(ip, {})
        top_ips.append({
            "ip":      ip,
            "count":   b["doc_count"],
            "country": geo.get("country", "") if isinstance(geo, dict) else "",
            "org":     geo.get("org", "") if isinstance(geo, dict) else "",
        })

    uncached = [x["ip"] for x in top_ips if not x.get("country")]
    if uncached:
        resolve_missing_ips_async(uncached)

    # User agents — clean printable ones only
    top_uas = []
    for b in aggs.get("top_ua", {}).get("buckets", []):
        ua = b["key"]
        if len(ua) > 10 and all(32 <= ord(c) <= 126 for c in ua[:80]):
            top_uas.append({"ua": ua[:200], "count": b["doc_count"]})

    # High-severity probe IPs
    hs_probes = aggs.get("high_severity_probes", {})
    threat_ips = []
    for b in hs_probes.get("by_ip", {}).get("buckets", []):
        ip  = b["key"]
        geo = geo_lookup.get(ip, {})
        threat_ips.append({
            "ip":      ip,
            "count":   b["doc_count"],
            "country": geo.get("country", "") if isinstance(geo, dict) else "",
        })
    threat_paths = [b["key"] for b in hs_probes.get("by_path", {}).get("buckets", [])]

    # Timeline — map eventid buckets to 2xx/4xx/5xx display categories
    # (http_status stored as keyword string so numeric range agg fails)
    PROBE_EIDS = {"nginx.probe.env_file","nginx.probe.git","nginx.probe.wordpress",
        "nginx.probe.tomcat","nginx.probe.router","nginx.probe.hikvision",
        "nginx.probe.log4shell","nginx.probe.404","nginx.request.bad"}
    timeline = []
    for b in aggs.get("timeline", {}).get("buckets", []):
        pt = {"ts": b["key"], "time": b.get("key_as_string", ""), "total": b["doc_count"],
              "2xx": 0, "4xx": 0, "5xx": 0}
        for eb in b.get("by_eventid", {}).get("buckets", []):
            eid = eb.get("key", ""); cnt = eb.get("doc_count", 0)
            if eid in PROBE_EIDS:         pt["4xx"] += cnt
            elif eid == "nginx.request.success": pt["2xx"] += cnt
            else:                          pt["5xx"] += cnt
        timeline.append(pt)

    return {
        "total":          total,
        "unique_ips":     aggs.get("unique_ips",   {}).get("value", 0),
        "unique_paths":   aggs.get("unique_paths", {}).get("value", 0),
        "methods":        methods,
        "status_codes":   status_codes,
        "top_paths":      top_paths,
        "path_categories": path_cats,
        "scanners":       scanners,
        "top_ips":        top_ips,
        "top_uas":        top_uas,
        "threat_ips":     threat_ips,
        "threat_paths":   threat_paths,
        "timeline":       timeline,
        "window_minutes": minutes,
        "as_of":          datetime.now(timezone.utc).isoformat(),
    }


# ============================================================
# Triage report
# ============================================================
def get_triage_report():
    try:
        with open(TRIAGE_REPORT) as f:
            return json.load(f)
    except Exception:
        return {}


# ============================================================
# Background runners
# ============================================================
def run_refresh_thread():
    global refresh_state
    refresh_state.update({
        "running": True, "error": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
    })
    # Step 1: Enrich Cowrie logs
    refresh_state["progress"] = "Step 1/3: Enriching logs with GeoIP..."
    try:
        subprocess.run([PYTHON, ENRICH_SCRIPT], timeout=180, capture_output=True)
    except Exception as e:
        refresh_state["error"] = str(e)

    # Step 2: Resolve ALL alert IPs from OpenSearch into cache
    refresh_state["progress"] = "Step 2/3: Resolving all attacker IPs via MaxMind..."
    try:
        total, resolved = resolve_alert_ips()
        refresh_state["progress"] = f"Step 2/3: Resolved {resolved} new IPs ({total} total in cache)"
    except Exception as e:
        refresh_state["error"] = str(e)

    # Step 3: Export to Wazuh format
    refresh_state["progress"] = "Step 3/3: Exporting to Wazuh format..."
    try:
        subprocess.run([PYTHON, EXPORT_SCRIPT,
            "--input", "/opt/cowrie-logs/cowrie_enriched.json",
            "--output-dir", "/opt/cowrie-logs/wazuh/",
            "--wazuh-manager", "127.0.0.1"],
            timeout=180, capture_output=True)
    except Exception as e:
        refresh_state["error"] = str(e)
    refresh_state["running"]  = False
    refresh_state["progress"] = "Complete"


def run_analysis_thread(mode, minutes, limit):
    global analysis_state
    analysis_state.update({
        "running": True, "error": None, "step": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
    })
    analysis_state.update({"progress": "Step 1/4: Enriching logs...", "step": 1})
    try:
        subprocess.run([PYTHON, ENRICH_SCRIPT], timeout=180, capture_output=True)
    except Exception:
        pass
    analysis_state.update({"progress": "Step 2/4: Exporting to Wazuh format...", "step": 2})
    try:
        subprocess.run([PYTHON, EXPORT_SCRIPT, "--input", "/opt/cowrie-logs/cowrie_enriched.json",
            "--output-dir", "/opt/cowrie-logs/wazuh/", "--wazuh-manager", "127.0.0.1"],
            timeout=180, capture_output=True)
    except Exception:
        pass
    analysis_state.update({"progress": "Step 3/4: Polling alerts from OpenSearch...", "step": 3})
    try:
        result = subprocess.run([PYTHON, POLLER_SCRIPT, "--minutes", str(minutes),
            "--min-level", "6", "--limit", str(limit), "--honeypot-only", "--output", ALERTS_RAW],
            timeout=120, capture_output=True)
        if result.returncode != 0:
            analysis_state["error"] = "Poll step failed"
            analysis_state["running"] = False
            return
    except Exception as e:
        analysis_state["error"] = str(e)
        analysis_state["running"] = False
        return
    analysis_state.update({"progress": f"Step 4/4: Running AI analysis ({mode})...", "step": 4})
    try:
        result = subprocess.run([PYTHON, TRIAGE_SCRIPT, "--mode", mode,
            "--input", ALERTS_RAW, "--output", TRIAGE_REPORT, "--minutes", str(minutes)],
            timeout=600, capture_output=True, text=True)
        if result.returncode != 0:
            analysis_state["error"] = (result.stderr or "")[-300:]
    except subprocess.TimeoutExpired:
        analysis_state["error"] = "Analysis timed out (>10 min) — try Summary mode"
    except Exception as e:
        analysis_state["error"] = str(e)
    analysis_state["running"]  = False
    analysis_state["progress"] = "Complete"


# ============================================================
# Botnet AI Analysis
# ============================================================
def analyze_botnet_with_ai(name, count, unique_ips):
    """Use Ollama to generate a botnet analysis summary."""
    import ssl as _ssl
    OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://100.72.171.104:11434/api/generate")

    # Get sample events for this botnet to give AI real context
    # Build query dynamically from botnet name — works with auto-detected campaigns
    if name == "Telnet Scanner":
        query = {"term": {"data.protocol": "telnet"}}
    elif "SSH Key Implant" in name:
        query = {"wildcard": {"data.input": "*ssh-rsa*"}}
    elif "chattr" in name.lower() or "Anti-Forensic" in name:
        query = {"wildcard": {"data.input": "*chattr*"}}
    elif "Downloader" in name:
        query = {"bool": {"should": [
            {"wildcard": {"data.input": "*wget*"}},
            {"wildcard": {"data.input": "*curl*"}},
        ], "minimum_should_match": 1}}
    elif "Recon" in name:
        query = {"term": {"data.input": "uname -s -v -n -r -m"}}
    elif "BusyBox" in name:
        query = {"wildcard": {"data.input": "*busybox*"}}
    elif "Campaign" in name or "Scanner" in name or "Brute Force" in name:
        # Extract the key term from the name and search credentials/commands
        key = name.replace(" Campaign","").replace(" Scanner","").replace(" Brute Force","").strip()
        query = {"bool": {"should": [
            {"wildcard": {"data.password": f"*{key}*"}},
            {"wildcard": {"data.username": f"*{key}*"}},
            {"wildcard": {"data.input":    f"*{key}*"}},
        ], "minimum_should_match": 1}}
    else:
        query = {"bool": {"should": [
            {"wildcard": {"data.password": f"*{name.split()[0]}*"}},
            {"wildcard": {"data.input":    f"*{name.split()[0]}*"}},
        ], "minimum_should_match": 1}}
    sample_body = {
        "size": 25,
        "query": {"bool": {"filter": [
            {"exists": {"field": "data.honeypot"}},
            query,
        ]}},
        "_source": ["data.src_ip", "data.username", "data.password",
                    "data.input", "data.eventid", "data.timestamp"],
        "sort": [{"data.timestamp": "desc"}],
    }
    sample_result = os_query(f"/{ALERT_INDEX}/_search", sample_body)
    samples = []
    for h in sample_result.get("hits", {}).get("hits", []):
        d = h.get("_source", {}).get("data", {})
        samples.append({
            "ip":      d.get("src_ip", ""),
            "user":    d.get("username", ""),
            "pass":    d.get("password", ""),
            "cmd":     (d.get("input", "") or "")[:80],
            "eventid": d.get("eventid", ""),
        })

    prompt = f"""You are a threat intelligence analyst. Analyze this botnet detected in a Cowrie SSH honeypot.

Botnet: {name}
Total events: {count:,}
Unique source IPs: {unique_ips}

Sample events:
{json.dumps(samples, indent=2)}

Provide a SHORT analysis (2-3 sentences each section). Respond with ONLY valid JSON:
{{
  "description": "What this botnet is, its name/family if known, and its primary purpose",
  "methodology": "How it operates — what credentials it uses, what commands it runs, attack pattern",
  "detection": "How it was recognized in this honeypot — specific signatures, credential patterns, command sequences",
  "threat_level": "Threat assessment — sophistication level, risk, what damage it could do on a real system"
}}"""

    # Ollama call with retry logic and fallback template
    _OLLAMA_FALLBACK = {
        "description": "AI analysis unavailable — Ollama may be offline or busy.",
        "methodology": "Unable to generate analysis at this time.",
        "detection": "Campaign was detected via credential/command clustering.",
        "threat_level": "Manual review recommended.",
    }
    # Fast reachability pre-check: if Ollama's host is down (e.g. laptop asleep),
    # fail in ~3s instead of waiting out the full generation timeout twice.
    try:
        _tags_url = OLLAMA_URL.replace("/api/generate", "/api/tags")
        import ssl as _ssl_pc
        _ctx_pc = _ssl_pc.create_default_context()
        _ctx_pc.check_hostname = False
        _ctx_pc.verify_mode = _ssl_pc.CERT_NONE
        urllib.request.urlopen(
            urllib.request.Request(_tags_url, method="GET"),
            timeout=3, context=_ctx_pc,
        )
    except Exception as _pc_err:
        log.warning("Ollama pre-check failed (%s) — returning fallback without waiting", _pc_err)
        return dict(_OLLAMA_FALLBACK)

    for _attempt in range(2):
        try:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            body = json.dumps({
                "model": "llama3.1:8b",
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.3, "num_predict": 2048},
            }).encode()
            req = urllib.request.Request(
                OLLAMA_URL, data=body,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=90) as r:
                result = json.loads(r.read().decode())
            raw = result.get("response", "")
            if not raw:
                raise ValueError("Empty response from Ollama")
            # Strip markdown code fences if present
            if "```" in raw:
                raw = raw.split("```")[1]
                if raw.startswith("json"): raw = raw[4:]
            # Validate JSON before returning
            parsed = json.loads(raw.strip())
            if not isinstance(parsed, dict):
                raise ValueError(f"Unexpected response type: {type(parsed)}")
            return parsed
        except urllib.error.URLError:
            if _attempt == 0:
                log.warning("Ollama unreachable, retrying in 2s...")
                time.sleep(2)
            else:
                log.error("Ollama unreachable after 2 attempts — returning fallback")
                return _OLLAMA_FALLBACK
        except json.JSONDecodeError as e:
            log.warning("Ollama returned invalid JSON: %s", e)
            return _OLLAMA_FALLBACK
        except Exception as e:
            log.error("Ollama error: %s", e)
            return {"error": str(e)}
    return _OLLAMA_FALLBACK


# ============================================================
# Routes
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def api_health():
    """Health check — verifies OpenSearch connectivity and GeoIP cache."""
    status = {"opensearch": "unknown", "geoip_cache": 0, "timestamp": datetime.now(timezone.utc).isoformat()}
    try:
        req = urllib.request.Request(
            f"{OPENSEARCH_URL}/_cluster/health",
            headers={"Authorization": AUTH_HEADER, "Content-Type": "application/json"},
            method="GET")
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=5) as r:
            health = json.loads(r.read().decode())
            status["opensearch"] = health.get("status", "unknown")
            status["active_shards"] = health.get("active_shards", 0)
    except Exception as e:
        status["opensearch"] = "error"
        # Sanitize error — don't expose Python internals
        err = str(e)
        if "refused" in err.lower() or "connect" in err.lower():
            status["opensearch_error"] = "Connection refused"
        elif "timeout" in err.lower():
            status["opensearch_error"] = "Connection timeout"
        elif "401" in err or "403" in err or "credential" in err.lower():
            status["opensearch_error"] = "Authentication failed"
        elif "ssl" in err.lower() or "certificate" in err.lower():
            status["opensearch_error"] = "SSL error"
        else:
            status["opensearch_error"] = "Unreachable"
    try:
        with open("/opt/cowrie-logs/geoip_cache.json") as f:
            cache = json.load(f)
            status["geoip_cache"] = len(cache)
    except Exception:
        status["geoip_cache"] = 0
    return jsonify(status)

@app.route("/api/stats")
@rate_limit(max_per_minute=30)
def api_stats():
    minutes = int(request.args.get("minutes", 60))
    return jsonify(get_live_stats(minutes))

@app.route("/api/attack_chain")
def api_attack_chain():
    minutes = int(request.args.get("minutes", 1440))
    return jsonify(get_attack_chain(minutes))

@app.route("/api/intel")
def api_intel():
    """Runs attack_chain, sessions, botnets, cred_intel IN PARALLEL — faster than 6 separate calls."""
    try:
        minutes = int(request.args.get("minutes", 1440))
        minutes = max(1, min(minutes, 129600))
    except (ValueError, TypeError):
        minutes = 1440
    with ThreadPoolExecutor(max_workers=4) as ex:
        f_chain = ex.submit(get_attack_chain, minutes)
        f_sess  = ex.submit(get_sessions,     minutes)
        f_bots  = ex.submit(get_botnets,      minutes)
        f_cred  = ex.submit(get_credential_intel, minutes)
        chain = f_chain.result()
        sess  = f_sess.result()
        bots  = f_bots.result()
        cred  = f_cred.result()
    return jsonify({
        "attack_chain": chain,
        "sessions":     sess,
        "botnets":      bots,
        "cred_intel":   cred,
    })


@app.route("/api/velocity")
def api_velocity():
    return jsonify(get_velocity())

@app.route("/api/heatmap")
def api_heatmap():
    return jsonify(get_heatmap())

@app.route("/api/sessions")
def api_sessions():
    minutes = int(request.args.get("minutes", 1440))
    return jsonify(get_sessions(minutes))

@app.route("/api/botnets")
@rate_limit(max_per_minute=10)  # Expensive parallel queries
def api_botnets():
    minutes = int(request.args.get("minutes", 10080))
    return jsonify(get_botnets(minutes))

@app.route("/api/botnet_analysis", methods=["POST"])
def api_botnet_analysis():
    """Fetch AI analysis for a detected campaign. POST: {name, count, unique_ips}"""
    data = request.get_json(force=True, silent=True) or {}
    name = re.sub(r'[^ -~]', '', str(data.get("name", "")).strip())[:100]
    if not name:
        return jsonify({"error": "Campaign name is required"}), 400
    try:
        count      = max(0, int(data.get("count", 0)))
        unique_ips = max(0, int(data.get("unique_ips", 0)))
    except (ValueError, TypeError):
        count = 0; unique_ips = 0
    result     = analyze_botnet_with_ai(name, count, unique_ips)
    return jsonify(result)


@app.route("/api/cred_intel")
def api_cred_intel():
    minutes = int(request.args.get("minutes", 10080))
    return jsonify(get_credential_intel(minutes))

@app.route("/api/dionaea")
@rate_limit(max_per_minute=10)
def api_dionaea():
    """Dionaea malware honeypot stats — service breakdown, binaries, top IPs."""
    try:
        minutes = int(request.args.get("minutes", 10080))
        minutes = max(1, min(minutes, 129600))
    except (ValueError, TypeError):
        minutes = 10080
    return jsonify(get_dionaea_stats(minutes))


@app.route("/api/nginx")
@rate_limit(max_per_minute=10)
def api_nginx():
    """nginx web honeypot stats — paths, scanners, user agents, timeline."""
    try:
        minutes = int(request.args.get("minutes", 10080))
        minutes = max(1, min(minutes, 129600))
    except (ValueError, TypeError):
        minutes = 10080
    return jsonify(get_nginx_stats(minutes))


@app.route("/api/honeypots")
@rate_limit(max_per_minute=10)
def api_honeypots():
    """Combined Dionaea + nginx stats in one parallel call.

    Returns:
        {"dionaea": {...}, "nginx": {...}}
    """
    try:
        minutes = int(request.args.get("minutes", 10080))
        minutes = max(1, min(minutes, 129600))
    except (ValueError, TypeError):
        minutes = 10080
    with ThreadPoolExecutor(max_workers=2) as ex:
        f_dio  = ex.submit(get_dionaea_stats, minutes)
        f_nginx = ex.submit(get_nginx_stats,   minutes)
        dio   = f_dio.result()
        nginx = f_nginx.result()
    return jsonify({"dionaea": dio, "nginx": nginx})


@app.route("/api/honeypot_health")
@rate_limit(max_per_minute=30)
def api_honeypot_health():
    """Per-honeypot health: event count in last hour + last-seen timestamp.

    Returns uptime-style status for each honeypot so the dashboard can show
    green/red indicators. 'healthy' = at least one event in the last 60 min.
    """
    now = datetime.now(timezone.utc)
    since_1h = (now - timedelta(hours=1)).isoformat()

    def _health(honeypot_name):
        body = {
            "size": 1,
            "track_total_hits": True,
            "query": {
                "bool": {"filter": [
                    {"range": {"@timestamp": {"gte": since_1h}}},
                    {"term":  {"data.honeypot": honeypot_name}},
                ]}
            },
            "sort": [{"@timestamp": "desc"}],
            "_source": ["@timestamp"],
        }
        result = os_query(f"/{ALERT_INDEX}/_search", body)
        if "error" in result:
            return {"status": "error", "events_1h": 0, "last_seen": None}
        hits  = result.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        last_seen = None
        hit_list = hits.get("hits", [])
        if hit_list:
            last_seen = hit_list[0].get("_source", {}).get("@timestamp")
        return {
            "status":    "healthy" if total > 0 else "idle",
            "events_1h": total,
            "last_seen": last_seen,
        }

    with ThreadPoolExecutor(max_workers=3) as ex:
        f_cow = ex.submit(_health, "cowrie")
        f_dio = ex.submit(_health, "dionaea")
        f_ngx = ex.submit(_health, "nginx")
        return jsonify({
            "cowrie":  f_cow.result(),
            "dionaea": f_dio.result(),
            "nginx":   f_ngx.result(),
            "as_of":   now.isoformat(),
        })


@app.route("/api/export")
@rate_limit(max_per_minute=6)
def api_export():
    """Export dashboard findings as JSON or CSV.

    Query params:
        format = json (default) | csv
        type   = ips | credentials | botnets | full   (csv requires a type)
        minutes = time window (default 1440)

    JSON returns the complete combined dashboard state for archival/SOAR.
    CSV returns a single table suitable for spreadsheet import.
    """
    fmt   = request.args.get("format", "json").lower()
    etype = request.args.get("type", "full").lower()
    try:
        minutes = max(1, min(int(request.args.get("minutes", 1440)), 129600))
    except (ValueError, TypeError):
        minutes = 1440

    if fmt == "json":
        with ThreadPoolExecutor(max_workers=4) as ex:
            f_stats = ex.submit(get_live_stats,        minutes)
            f_bots  = ex.submit(get_botnets,           minutes)
            f_cred  = ex.submit(get_credential_intel,  minutes)
            f_hp    = ex.submit(lambda: {
                "dionaea": get_dionaea_stats(minutes),
                "nginx":   get_nginx_stats(minutes),
            })
            payload = {
                "exported_at":    datetime.now(timezone.utc).isoformat(),
                "window_minutes": minutes,
                "stats":          f_stats.result(),
                "botnets":        f_bots.result(),
                "cred_intel":     f_cred.result(),
                "honeypots":      f_hp.result(),
            }
        resp = Response(json.dumps(payload, indent=2), mimetype="application/json")
        resp.headers["Content-Disposition"] = (
            f"attachment; filename=soc-export-{minutes}min.json"
        )
        return resp

    # ── CSV export ──────────────────────────────────────────────
    import csv
    import io
    out = io.StringIO()
    writer = csv.writer(out)

    if etype == "ips":
        stats = get_live_stats(minutes)
        writer.writerow(["ip", "country", "org", "alert_count"])
        for ip in stats.get("top_ips", []):
            writer.writerow([
                ip.get("ip", ""), ip.get("country", ""),
                ip.get("org", ""), ip.get("count", 0),
            ])
        fname = f"soc-ips-{minutes}min.csv"

    elif etype == "credentials":
        stats = get_live_stats(minutes)
        es = stats.get("enriched_stats", {})
        writer.writerow(["credential", "attempts"])
        for c in es.get("top_credentials", []):
            writer.writerow([c.get("cred", ""), c.get("count", 0)])
        fname = f"soc-credentials-{minutes}min.csv"

    elif etype == "botnets":
        bots = get_botnets(minutes)
        writer.writerow(["campaign", "events", "unique_ips"])
        for b in bots.get("botnets", []):
            writer.writerow([
                b.get("name", ""), b.get("count", 0),
                b.get("unique_ips", 0),
            ])
        fname = f"soc-botnets-{minutes}min.csv"

    else:
        return jsonify({"error": "csv export requires type=ips|credentials|botnets"}), 400

    resp = Response(out.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = f"attachment; filename={fname}"
    return resp


@app.route("/api/triage")
def api_triage():
    return jsonify(get_triage_report())

@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    global refresh_state
    if refresh_state["running"]:
        return jsonify({"error": "Refresh already running"}), 409
    threading.Thread(target=run_refresh_thread, daemon=True).start()
    return jsonify({"status": "started"})

@app.route("/api/refresh/status")
def api_refresh_status():
    return jsonify(refresh_state)

@app.route("/api/analysis/run", methods=["POST"])
def api_run_analysis():
    """Start an AI triage analysis run. POST: {mode, minutes, limit}"""
    global analysis_state
    if analysis_state["running"]:
        return jsonify({"error": "Analysis already running — wait for current run to complete"}), 409
    data = request.get_json(force=True, silent=True) or {}
    mode = str(data.get("mode", "summary")).strip().lower()
    if mode not in ("summary", "full", "executive"):
        return jsonify({"error": "mode must be: summary, full, or executive"}), 400
    try:
        minutes = max(1,  min(int(data.get("minutes", 1440)), 129600))
        limit   = max(10, min(int(data.get("limit",   100)),  500))
    except (ValueError, TypeError):
        return jsonify({"error": "minutes and limit must be integers"}), 400

    threading.Thread(target=run_analysis_thread, args=(mode, minutes, limit), daemon=True).start()
    return jsonify({"status": "started", "mode": mode, "minutes": minutes, "limit": limit})

@app.route("/api/analysis/status")
def api_analysis_status():
    return jsonify(analysis_state)


# ============================================================
# NEW: Alert detail, search, playbooks, cases (Project 4 sprint)
# ============================================================
_IP_RE = re.compile(r"^[0-9a-fA-F:.]{3,45}$")  # permissive IPv4/IPv6 sanity check

def _valid_ip(ip: str) -> bool:
    return bool(ip) and bool(_IP_RE.match(ip)) and len(ip) <= 45


def get_alert_context(ip: str, minutes: int = 10080) -> Dict:
    """Full context for one source IP: summary, last events, geo timeline, commands.

    Used by the Alert Details drawer. Pulls from the live Wazuh index.
    """
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    geo_lookup = build_geoip_lookup()
    geo = geo_lookup.get(ip, {}) if isinstance(geo_lookup.get(ip, {}), dict) else {}

    base_filter = [
        {"range": {"data.timestamp": {"gte": since.isoformat()}}},
        {"term":  {"data.src_ip": ip}},
    ]

    # 1) Aggregate summary + last 10 events in one query
    body = {
        "size": 10,
        "track_total_hits": True,
        "query": {"bool": {"filter": base_filter}},
        "sort": [{"data.timestamp": "desc"}],
        "_source": ["@timestamp", "data.timestamp", "data.eventid", "data.honeypot",
                    "data.username", "data.password", "data.input", "data.command",
                    "data.session", "data.dst_port", "rule.level", "rule.description",
                    "rule.mitre", "data.location.country_name"],
        "aggs": {
            "max_level":   {"max": {"field": "rule.level"}},
            "honeypots":   {"terms": {"field": "data.honeypot", "size": 10}},
            "eventids":    {"terms": {"field": "data.eventid", "size": 20}},
            "sessions":    {"cardinality": {"field": "data.session"}},
            "first_seen":  {"min": {"field": "data.timestamp"}},
            "last_seen":   {"max": {"field": "data.timestamp"}},
        },
    }
    result = os_query(f"/{ALERT_INDEX}/_search", body)
    if "error" in result:
        return {"error": result["error"], "ip": ip}

    hits  = result.get("hits", {})
    aggs  = result.get("aggregations", {})
    total = hits.get("total", {}).get("value", 0)

    last_events = []
    full_alert  = None
    for h in hits.get("hits", []):
        src  = h.get("_source", {})
        data = src.get("data", {})
        rule = src.get("rule", {})
        ev = {
            "ts":       data.get("timestamp") or src.get("@timestamp", ""),
            "eventid":  data.get("eventid", ""),
            "honeypot": data.get("honeypot", ""),
            "level":    rule.get("level", 0),
            "desc":     rule.get("description", ""),
            "username": data.get("username", ""),
            "password": data.get("password", ""),
            "command":  (data.get("input", "") or data.get("command", "") or "")[:200],
            "session":  data.get("session", ""),
            "dst_port": data.get("dst_port", ""),
        }
        last_events.append(ev)
        if full_alert is None:
            full_alert = h.get("_source", {})  # the most recent raw alert (full JSON)

    # 2) Recent commands for this IP
    body_cmd = {
        "size": 0,
        "query": {"bool": {"filter": base_filter + [
            {"term": {"data.eventid": "cowrie.command.input"}},
        ]}},
        "aggs": {"cmds": {"terms": {"field": "data.input", "size": 25, "order": {"_count": "desc"}}}},
    }
    cmd_res = os_query(f"/{ALERT_INDEX}/_search", body_cmd)
    commands = [
        {"cmd": b["key"], "count": b["doc_count"]}
        for b in cmd_res.get("aggregations", {}).get("cmds", {}).get("buckets", [])
    ]

    # 3) Geographic / activity timeline (bucketed)
    body_tl = {
        "size": 0,
        "query": {"bool": {"filter": base_filter}},
        "aggs": {"tl": {"date_histogram": {
            "field": "data.timestamp", "fixed_interval": "1h", "min_doc_count": 1,
        }}},
    }
    tl_res = os_query(f"/{ALERT_INDEX}/_search", body_tl)
    timeline = [
        {"time": b.get("key_as_string", ""), "ts": b.get("key", 0), "count": b.get("doc_count", 0)}
        for b in tl_res.get("aggregations", {}).get("tl", {}).get("buckets", [])
    ]

    return {
        "ip":          ip,
        "country":     geo.get("country", "") or "",
        "city":        geo.get("city", "") or "",
        "org":         geo.get("org", "") or "",
        "total_events": total,
        "max_level":   int(aggs.get("max_level", {}).get("value") or 0),
        "sessions":    int(aggs.get("sessions", {}).get("value") or 0),
        "first_seen":  aggs.get("first_seen", {}).get("value_as_string", ""),
        "last_seen":   aggs.get("last_seen", {}).get("value_as_string", ""),
        "honeypots":   {b["key"]: b["doc_count"] for b in aggs.get("honeypots", {}).get("buckets", [])},
        "eventids":    {b["key"]: b["doc_count"] for b in aggs.get("eventids", {}).get("buckets", [])},
        "last_events": last_events,
        "commands":    commands,
        "timeline":    timeline,
        "full_alert":  full_alert or {},
        "window_minutes": minutes,
    }


@app.route("/api/alert/<ip>")
@rate_limit(max_per_minute=60)
def api_alert(ip):
    """Full drawer context for a single source IP."""
    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP"}), 400
    try:
        minutes = max(1, min(int(request.args.get("minutes", 10080)), 129600))
    except (ValueError, TypeError):
        minutes = 10080
    return jsonify(get_alert_context(ip, minutes))


# ============================================================
# Attacker narrative — unified cross-honeypot story for ONE IP
# ============================================================
# Maps cowrie/dionaea/nginx eventids onto the kill-chain phase they represent,
# so a single IP's activity across all three honeypots can be told as one
# ordered story rather than three siloed event lists.
_PHASE_ORDER = ["recon", "access", "execution", "download", "persistence", "exfil", "other"]

def _phase_for_event(eid: str, command: str = "") -> str:
    eid = eid or ""
    cmd = command or ""
    if eid.startswith("nginx.probe.") or eid in ("cowrie.session.connect", "dionaea.connection") \
            or eid.startswith("dionaea.connection.") or eid == "nginx.probe.404":
        return "recon"
    if eid in ("cowrie.login.success",) or eid.endswith(".login.smb") or eid.endswith(".login.ftp") \
            or eid == "cowrie.login.failed":
        return "access"
    if eid == "cowrie.command.input":
        if "ssh-rsa" in cmd or "authorized_keys" in cmd or "chattr" in cmd:
            return "persistence"
        if any(t in cmd for t in ("wget", "curl", "tftp", "ftpget", "scp")):
            return "download"
        return "execution"
    if eid in ("cowrie.session.file_download", "dionaea.binary.captured"):
        return "download"
    if eid.startswith("dionaea.incident.") or eid == "nginx.probe.log4shell":
        return "execution"
    return "other"


def get_attack_narrative(ip: str, minutes: int = 43200) -> Dict:
    """Reconstruct a single attacker's complete, ordered story across ALL three
    honeypots, plus a compiled IOC block. This is the correlation view: it turns
    siloed per-honeypot events into one coherent kill-chain narrative for one IP.
    """
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    since_iso = since.isoformat()
    base = [
        {"range": {"data.timestamp": {"gte": since_iso}}},
        {"term":  {"data.src_ip": ip}},
    ]
    geo = build_geoip_lookup().get(ip, {})
    geo = geo if isinstance(geo, dict) else {}

    # 1) Per-honeypot + per-phase counts, distinct sessions, time bounds
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": base}},
        "aggs": {
            "honeypots":  {"terms": {"field": "data.honeypot", "size": 6}},
            "eventids":   {"terms": {"field": "data.eventid", "size": 40}},
            "sessions":   {"cardinality": {"field": "data.session"}},
            "max_level":  {"max": {"field": "rule.level"}},
            "first_seen": {"min": {"field": "data.timestamp"}},
            "last_seen":  {"max": {"field": "data.timestamp"}},
            "mitre":      {"terms": {"field": "rule.mitre.tactic", "size": 15}},
            "countries":  {"terms": {"field": "data.location.country_name", "size": 3}},
            # credential pairs tried (and whether each succeeded)
            "creds_tried": {"terms": {
                "script": {"lang": "painless",
                           "source": ("doc['data.username'].size() > 0 && doc['data.password'].size() > 0 "
                                      "? doc['data.username'].value + '/' + doc['data.password'].value : null")},
                "size": 25, "order": {"_count": "desc"}}},
            "creds_ok": {"filter": {"term": {"data.eventid": "cowrie.login.success"}},
                         "aggs": {"pairs": {"terms": {
                             "script": {"lang": "painless",
                                        "source": ("doc['data.username'].size() > 0 && doc['data.password'].size() > 0 "
                                                   "? doc['data.username'].value + '/' + doc['data.password'].value : null")},
                             "size": 10}}}},
            # command frequency (the "what did they run" view)
            "commands": {"filter": {"term": {"data.eventid": "cowrie.command.input"}},
                         "aggs": {"by_cmd": {"terms": {"field": "data.input", "size": 40,
                                                        "order": {"_count": "desc"}}}}},
            # malware delivered (dionaea), with VT verdict
            "malware": {"filter": {"term": {"data.eventid": "dionaea.binary.captured"}},
                        "aggs": {"hashes": {"terms": {"field": "data.sha256", "size": 10},
                                            "aggs": {"doc": {"top_hits": {"size": 1,
                                                "sort": [{"data.timestamp": "desc"}],
                                                "_source": ["data.sha256", "data.md5", "data.file_size",
                                                            "data.service", "data.vt_malicious", "data.vt_total",
                                                            "data.vt_label", "data.vt_permalink", "data.download_url"]}}}}}},
            # web CVE / exploit probes (nginx)
            "cve_probes": {"terms": {"field": "data.eventid", "size": 15, "include": "nginx.probe.*"}},
            "web_paths":  {"terms": {"field": "data.http_path", "size": 15, "order": {"_count": "desc"}}},
            "user_agents": {"terms": {"field": "data.user_agent", "size": 5}},
            "dst_ports":  {"terms": {"field": "data.dst_port", "size": 10}},
            "services":   {"terms": {"field": "data.service", "size": 8}},
        },
    }
    res = os_query(f"/{ALERT_INDEX}/_search", body)
    if "error" in res:
        return {"error": res["error"], "ip": ip}
    aggs = res.get("aggregations", {})
    total = res.get("hits", {}).get("total", {}).get("value", 0)

    eventids = {b["key"]: b["doc_count"] for b in aggs.get("eventids", {}).get("buckets", [])}
    honeypots = {b["key"]: b["doc_count"] for b in aggs.get("honeypots", {}).get("buckets", [])}

    # Normalise vectors
    vectors = set()
    for h in honeypots:
        if "cowrie" in h: vectors.add("ssh")
        elif "dionaea" in h: vectors.add("malware")
        elif "nginx" in h: vectors.add("web")

    creds_tried = [{"cred": b["key"], "count": b["doc_count"]}
                   for b in aggs.get("creds_tried", {}).get("buckets", []) if b.get("key")]
    creds_ok = [b["key"] for b in aggs.get("creds_ok", {}).get("pairs", {}).get("buckets", []) if b.get("key")]
    ok_set = set(creds_ok)
    for c in creds_tried:
        c["success"] = c["cred"] in ok_set

    commands = [{"cmd": b["key"], "count": b["doc_count"]}
                for b in aggs.get("commands", {}).get("by_cmd", {}).get("buckets", []) if b.get("key")]

    malware = []
    for hb in aggs.get("malware", {}).get("hashes", {}).get("buckets", []):
        hits = hb.get("doc", {}).get("hits", {}).get("hits", [])
        d = hits[0].get("_source", {}).get("data", {}) if hits else {}
        malware.append({
            "sha256": hb["key"], "sha256_short": (hb["key"] or "")[:16] + "…",
            "count": hb["doc_count"], "md5": d.get("md5", ""), "file_size": d.get("file_size", ""),
            "service": d.get("service", ""), "vt_malicious": d.get("vt_malicious"),
            "vt_total": d.get("vt_total"), "vt_label": d.get("vt_label", ""),
            "vt_permalink": d.get("vt_permalink", ""), "download_url": d.get("download_url", ""),
        })

    cve_probes = [b["key"].replace("nginx.probe.", "") for b in aggs.get("cve_probes", {}).get("buckets", [])]
    web_paths  = [{"path": b["key"][:120], "count": b["doc_count"]}
                  for b in aggs.get("web_paths", {}).get("buckets", []) if b.get("key")]
    user_agents = [b["key"][:160] for b in aggs.get("user_agents", {}).get("buckets", []) if b.get("key")]
    dst_ports  = {str(b["key"]): b["doc_count"] for b in aggs.get("dst_ports", {}).get("buckets", [])}
    services   = {b["key"]: b["doc_count"] for b in aggs.get("services", {}).get("buckets", [])}
    mitre      = [b["key"] for b in aggs.get("mitre", {}).get("buckets", [])]

    # 1b) SIGNIFICANT EVENTS — reconstruct what actually happened, in order,
    #     excluding the cowrie-raw session noise (connect/closed/kex/version)
    #     that otherwise drowns out the meaningful actions.
    _NOISE_EVENTS = [
        "cowrie.session.connect", "cowrie.session.closed", "cowrie.log.closed",
        "cowrie.client.kex", "cowrie.client.version", "cowrie.client.size",
        "cowrie.session.params", "cowrie.direct-tcpip.request",
        "cowrie.direct-tcpip.data",
    ]
    sig_body = {
        "size": 60,
        "sort": [{"data.timestamp": {"order": "asc"}}],
        "_source": ["data.timestamp", "data.eventid", "data.honeypot", "data.input",
                    "data.username", "data.password", "data.http_method", "data.http_path",
                    "data.dst_port", "data.service", "rule.level", "rule.description",
                    "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id"],
        "query": {"bool": {
            "filter": base,
            "must_not": [{"terms": {"data.eventid": _NOISE_EVENTS}}],
        }},
    }
    sig_res = os_query(f"/{ALERT_INDEX}/_search", sig_body)
    significant_events = []
    tactic_evidence = {}   # tactic -> ordered list of {evidence, eventid, technique}
    if "error" not in sig_res:
        for h in sig_res.get("hits", {}).get("hits", []):
            s = h.get("_source", {})
            dd = s.get("data", {})
            rule = s.get("rule", {})
            mit = rule.get("mitre", {}) if isinstance(rule.get("mitre"), dict) else {}
            tactics = mit.get("tactic", []) or []
            if isinstance(tactics, str): tactics = [tactics]
            techniques = mit.get("technique", []) or []
            if isinstance(techniques, str): techniques = [techniques]
            eid = dd.get("eventid", "")
            cmd = dd.get("input", "")
            # human-readable evidence string for this event
            if cmd:
                evidence = cmd
            elif dd.get("http_path"):
                evidence = f"{dd.get('http_method','GET')} {dd.get('http_path','')}"
            elif dd.get("username") is not None:
                evidence = f"login {dd.get('username','')}/{dd.get('password','')}"
            else:
                evidence = rule.get("description", eid)
            ev = {
                "ts": dd.get("timestamp", ""),
                "eventid": eid,
                "honeypot": dd.get("honeypot", ""),
                "level": rule.get("level", 0),
                "desc": rule.get("description", ""),
                "command": cmd,
                "evidence": evidence[:200],
                "tactics": tactics,
                "techniques": techniques,
            }
            significant_events.append(ev)
            # map each tactic to the concrete evidence that triggered it
            for t in tactics:
                bucket = tactic_evidence.setdefault(t, [])
                # dedupe by evidence text, keep first few
                if evidence and not any(x["evidence"] == evidence[:200] for x in bucket) and len(bucket) < 4:
                    bucket.append({"evidence": evidence[:200], "eventid": eid,
                                   "techniques": techniques})
    # keep the most recent ~25 significant events for display (already asc-ordered)
    significant_events = significant_events[-25:]

    # 2) Persistence / TTP detection from commands
    persistence = []
    cmd_text = " \n ".join(c["cmd"] for c in commands)
    if "ssh-rsa" in cmd_text or "authorized_keys" in cmd_text:
        persistence.append({"type": "ssh_key_backdoor",
                            "label": "SSH authorized_keys backdoor implanted"})
    if "mdrfckr" in cmd_text:
        persistence.append({"type": "mdrfckr_botnet",
                            "label": "mdrfckr botnet RSA key (known campaign)"})
    if "chattr" in cmd_text:
        persistence.append({"type": "immutable_flag",
                            "label": "chattr immutable flag — anti-removal"})
    if any(k in cmd_text for k in ("crontab", "/etc/cron", "rc.local", "systemctl enable")):
        persistence.append({"type": "scheduled_task", "label": "cron / init persistence"})
    if any(k in cmd_text for k in ("useradd", "adduser", "/etc/passwd")):
        persistence.append({"type": "new_account", "label": "account creation attempt"})

    # 3) Build ordered kill-chain phase summary (which phases this actor reached)
    phase_hit = {p: 0 for p in _PHASE_ORDER}
    for eid, cnt in eventids.items():
        phase_hit[_phase_for_event(eid)] += cnt
    if any(c.get("success") for c in creds_tried):
        phase_hit["access"] += 0  # already counted; keep phase visible
    phases = [{"phase": p, "events": phase_hit[p]} for p in _PHASE_ORDER if phase_hit[p] > 0]

    # 4) Compile IOC block (the takeaway artifacts for a case)
    iocs = {
        "source_ip": ip,
        "country": geo.get("country", "") or "",
        "org": geo.get("org", "") or "",
        "credentials_succeeded": creds_ok,
        "malware_sha256": [m["sha256"] for m in malware if m["sha256"]],
        "malware_md5": [m["md5"] for m in malware if m.get("md5")],
        "cve_probes": cve_probes,
        "persistence": [p["type"] for p in persistence],
        "targeted_ports": list(dst_ports.keys()),
        "user_agents": user_agents,
    }

    # 5) Human-readable one-line narrative summary
    story = _compose_story(ip, geo, vectors, creds_tried, creds_ok, commands,
                           malware, cve_probes, persistence, total)

    return {
        "ip": ip,
        "country": geo.get("country", "") or "",
        "city": geo.get("city", "") or "",
        "org": geo.get("org", "") or "",
        "total_events": total,
        "sessions": int(aggs.get("sessions", {}).get("value") or 0),
        "max_level": int(aggs.get("max_level", {}).get("value") or 0),
        "first_seen": aggs.get("first_seen", {}).get("value_as_string", ""),
        "last_seen": aggs.get("last_seen", {}).get("value_as_string", ""),
        "vectors": sorted(vectors),
        "honeypots": honeypots,
        "phases": phases,
        "mitre_tactics": mitre,
        "tactic_evidence": tactic_evidence,
        "significant_events": significant_events,
        "credentials_tried": creds_tried,
        "credentials_succeeded": creds_ok,
        "commands": commands,
        "malware": malware,
        "cve_probes": cve_probes,
        "web_paths": web_paths,
        "user_agents": user_agents,
        "services": services,
        "dst_ports": dst_ports,
        "persistence": persistence,
        "iocs": iocs,
        "story": story,
        "window_minutes": minutes,
    }


def _compose_story(ip, geo, vectors, creds_tried, creds_ok, commands, malware,
                   cve_probes, persistence, total) -> str:
    """Plain-language one-paragraph summary of what this actor did."""
    loc = geo.get("country", "") or "an unknown location"
    org = geo.get("org", "")
    where = f"{loc}" + (f" ({org})" if org else "")
    vec_txt = " + ".join(sorted(vectors)) if vectors else "no recognised"
    parts = [f"{ip} from {where} generated {total:,} events across {vec_txt} vector(s)."]
    if creds_tried:
        if creds_ok:
            parts.append(f"It brute-forced SSH and SUCCEEDED with {len(creds_ok)} credential pair(s) "
                         f"({', '.join(creds_ok[:3])}), after trying {len(creds_tried)} combinations.")
        else:
            parts.append(f"It attempted {len(creds_tried)} credential pair(s) but did not succeed.")
    if commands:
        parts.append(f"Post-access it ran {len(commands)} distinct command(s).")
    if persistence:
        parts.append("Persistence: " + "; ".join(p["label"] for p in persistence) + ".")
    if malware:
        flagged = [m for m in malware if isinstance(m.get("vt_malicious"), int) and m["vt_malicious"]]
        if flagged:
            top = max(flagged, key=lambda m: m["vt_malicious"])
            parts.append(f"It delivered {len(malware)} binary/-ies; the most-flagged "
                         f"({top.get('vt_label') or 'malware'}) hit {top['vt_malicious']}/{top.get('vt_total','?')} "
                         f"VirusTotal engines.")
        else:
            parts.append(f"It delivered {len(malware)} binary/-ies over the malware honeypot.")
    if cve_probes:
        parts.append(f"On the web honeypot it probed: {', '.join(cve_probes[:6])}.")
    return " ".join(parts)


@app.route("/api/actor/<ip>")
@rate_limit(max_per_minute=60)
def api_actor(ip):
    """Unified cross-honeypot attack narrative + IOC block for a single IP."""
    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP"}), 400
    try:
        minutes = max(1, min(int(request.args.get("minutes", 43200)), 129600))
    except (ValueError, TypeError):
        minutes = 43200
    return jsonify(get_attack_narrative(ip, minutes))


@app.route("/api/search")
@rate_limit(max_per_minute=60)
def api_search():
    """Search by IP, credential, or command. type=ip|cred|cmd.

    Returns matching source IPs + a small set of example hits so the client
    can highlight related rows across panels.
    """
    q     = (request.args.get("q", "") or "").strip()
    stype = (request.args.get("type", "ip") or "ip").lower()
    try:
        minutes = max(1, min(int(request.args.get("minutes", 10080)), 129600))
    except (ValueError, TypeError):
        minutes = 10080
    if not q:
        return jsonify({"error": "q is required", "results": []}), 400
    if stype not in ("ip", "cred", "cmd"):
        return jsonify({"error": "type must be ip|cred|cmd"}), 400
    if len(q) > 200:
        return jsonify({"error": "query too long"}), 400

    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    flt = [{"range": {"data.timestamp": {"gte": since.isoformat()}}},
           {"exists": {"field": "data.honeypot"}}]

    if stype == "ip":
        flt.append({"wildcard": {"data.src_ip": f"*{q}*"}})
    elif stype == "cred":
        # match username or password substring
        flt.append({"bool": {"should": [
            {"wildcard": {"data.username": f"*{q}*"}},
            {"wildcard": {"data.password": f"*{q}*"}},
        ], "minimum_should_match": 1}})
    else:  # cmd
        flt.append({"wildcard": {"data.input": f"*{q}*"}})

    body = {
        "size": 25,
        "track_total_hits": True,
        "query": {"bool": {"filter": flt}},
        "sort": [{"data.timestamp": "desc"}],
        "_source": ["data.timestamp", "data.src_ip", "data.eventid", "data.honeypot",
                    "data.username", "data.password", "data.input", "rule.level", "rule.description"],
        "aggs": {"by_ip": {"terms": {"field": "data.src_ip", "size": 100}}},
    }
    result = os_query(f"/{ALERT_INDEX}/_search", body)
    if "error" in result:
        return jsonify({"error": result["error"], "results": []})

    hits = result.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    ips = [{"ip": b["key"], "count": b["doc_count"]}
           for b in result.get("aggregations", {}).get("by_ip", {}).get("buckets", [])]

    examples = []
    for h in hits.get("hits", []):
        s = h.get("_source", {}); d = s.get("data", {}); r = s.get("rule", {})
        examples.append({
            "ts": d.get("timestamp", ""), "ip": d.get("src_ip", ""),
            "eventid": d.get("eventid", ""), "honeypot": d.get("honeypot", ""),
            "username": d.get("username", ""), "password": d.get("password", ""),
            "command": (d.get("input", "") or "")[:120],
            "level": r.get("level", 0), "desc": r.get("description", ""),
        })

    return jsonify({
        "query": q, "type": stype, "total": total,
        "matched_ips": ips, "examples": examples,
    })


@app.route("/api/playbooks")
def api_playbooks():
    """Return the hardcoded response playbooks."""
    return jsonify(PLAYBOOKS)


def get_threat_actors(minutes: int, limit: int = 15) -> dict:
    """Cross-honeypot threat-actor correlation.

    For each source IP, aggregate its activity across ALL honeypots (Cowrie SSH,
    nginx web, Dionaea malware) into one unified profile, then rank by a composite
    threat score. This links behaviours that are otherwise siloed in separate
    panels: e.g. an IP that brute-forces SSH, probes web paths, AND delivers
    malware is one coordinated actor, not three unrelated blips.
    """
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    since_iso = since.isoformat()
    # Adaptive candidate pool: smaller for long windows to stay fast
    # under concurrent dashboard load (scan is sub-second even at 90d).
    _pool = 200 if minutes <= 20160 else 100  # 14 days = 20160 min

    # Two competing orderings matter here:
    #   • hp_card desc  → surfaces genuine multi-vector actors (the rare, most
    #     interesting IPs that hit SSH + web + malware).
    #   • max_lvl desc  → surfaces the highest-severity single-vector actors.
    # Ranking by only one of them is what collapsed the panel to "1 attacker" on
    # long windows: on a 7d+ window almost every IP is single-vector, so a pure
    # hp_card ordering returns a flat tie broken arbitrarily by doc_count, and one
    # hyperactive IP dominated. We pull a generous candidate set ordered by
    # severity (so high-impact actors are never missed) and compute the real
    # composite score in Python across ALL candidates, then rank.
    cred_script = ("doc['data.username'].size() > 0 && doc['data.password'].size() > 0 "
                   "? doc['data.username'].value + '/' + doc['data.password'].value : null")
    body = {
        "size": 0,
        "timeout": "30s",
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since_iso}}},
            {"exists": {"field": "data.src_ip"}},
            {"exists": {"field": "data.honeypot"}},
        ]}},
        "aggs": {
            "actors": {
                "terms": {"field": "data.src_ip", "size": _pool, "order": {"hp_card": "desc"}},
                "aggs": {
                    "hp_card":    {"cardinality": {"field": "data.honeypot"}},
                    "max_lvl":    {"max": {"field": "rule.level"}},
                    "honeypots":  {"terms": {"field": "data.honeypot", "size": 6}},
                    "eventids":   {"terms": {"field": "data.eventid", "size": 30}},
                    "first_seen": {"min": {"field": "data.timestamp"}},
                    "last_seen":  {"max": {"field": "data.timestamp"}},
                    "mitre":      {"terms": {"field": "rule.mitre.tactic", "size": 12}},
                    "got_malware": {"filter": {"term": {"data.eventid": "dionaea.binary.captured"}}},
                    "got_login":   {"filter": {"term": {"data.eventid": "cowrie.login.success"}}},
                    "got_cmds":    {"filter": {"term": {"data.eventid": "cowrie.command.input"}}},
                    # ── enrichment so the headline panel can render rich cards ──
                    "creds":      {"terms": {"field": "data.username", "size": 8, "order": {"_count": "desc"}}},
                    "cred_card":  {"cardinality": {"field": "data.username"}},
                    "top_cmds":   {"terms": {"field": "data.input", "size": 6, "order": {"_count": "desc"}}},
                    "countries":  {"terms": {"field": "data.location.country_name", "size": 1}},
                    # persistence / backdoor signal — SSH key implant (mdrfckr family)
                    "key_implant": {"filter": {"match_phrase": {"data.input": "ssh-rsa"}}},
                    "immutable":   {"filter": {"match_phrase": {"data.input": "chattr"}}},
                    # web CVE / exploit probes (nginx vectors)
                    "cve_probes":  {"terms": {"field": "data.eventid", "size": 12,
                                              "include": "nginx.probe.*"}},
                    "malware_fam": {"terms": {"field": "data.vt_label", "size": 4}},
                    "services":    {"terms": {"field": "data.service", "size": 8}},
                },
            }
        },
    }
    result = os_query(f"/{ALERT_INDEX}/_search", body)
    if "error" in result:
        return {"error": result["error"], "actors": []}

    geo = build_geoip_lookup()
    # Single candidate pool ordered by honeypot cardinality (hp_card) so genuine
    # multi-vector actors surface into the pool instead of being buried below the
    # level-14 SSH brute-force crowd. Final ranking is the Python composite score
    # below, which still floats multi-vector + high-severity actors to the top.
    actors = []
    for b in result.get("aggregations", {}).get("actors", {}).get("buckets", []):
        ip = b["key"]
        hps = {x["key"]: x["doc_count"] for x in b.get("honeypots", {}).get("buckets", [])}
        # normalise honeypot names (cowrie / cowrie-raw both = ssh)
        vectors = set()
        for h in hps:
            if "cowrie" in h: vectors.add("ssh")
            elif "dionaea" in h: vectors.add("malware")
            elif "nginx" in h: vectors.add("web")
        n_vectors = len(vectors)
        total = b["doc_count"]
        max_lvl = int(b.get("max_lvl", {}).get("value") or 0)
        malware = b.get("got_malware", {}).get("doc_count", 0)
        logins  = b.get("got_login", {}).get("doc_count", 0)
        cmds    = b.get("got_cmds", {}).get("doc_count", 0)
        mitre = [x["key"] for x in b.get("mitre", {}).get("buckets", [])]

        creds = [x["key"] for x in b.get("creds", {}).get("buckets", []) if x.get("key")]
        cred_card = int(b.get("cred_card", {}).get("value") or 0)
        top_cmds = [{"cmd": x["key"][:120], "count": x["doc_count"]}
                    for x in b.get("top_cmds", {}).get("buckets", []) if x.get("key")]
        key_implant = b.get("key_implant", {}).get("doc_count", 0) > 0
        immutable   = b.get("immutable", {}).get("doc_count", 0) > 0
        cve_probes  = [x["key"].replace("nginx.probe.", "")
                       for x in b.get("cve_probes", {}).get("buckets", [])]
        malware_fam = [x["key"] for x in b.get("malware_fam", {}).get("buckets", []) if x.get("key")]
        services    = {x["key"]: x["doc_count"] for x in b.get("services", {}).get("buckets", [])}
        eventids    = {x["key"]: x["doc_count"] for x in b.get("eventids", {}).get("buckets", [])}
        ctry_bkts   = b.get("countries", {}).get("buckets", [])
        ctry_evt    = ctry_bkts[0]["key"] if ctry_bkts else ""

        # Composite threat score: multi-vector actors and those who actually
        # breached (login/commands) or delivered malware rank highest.
        score = (n_vectors * 50) + min(max_lvl, 15) * 3 + (40 if malware else 0) \
                + (20 if logins else 0) + (10 if cmds else 0) + min(total // 100, 20) \
                + (15 if key_implant else 0) + (10 if cve_probes else 0)

        g = geo.get(ip, {}) if isinstance(geo.get(ip, {}), dict) else {}
        actors.append({
            "ip": ip,
            "country": g.get("country", "") or ctry_evt,
            "org": g.get("org", ""),
            "vectors": sorted(vectors),
            "n_vectors": n_vectors,
            "total_events": total,
            "max_level": max_lvl,
            "malware_delivered": malware,
            "ssh_login_success": logins,
            "commands_run": cmds,
            "mitre_tactics": mitre,
            "first_seen": b.get("first_seen", {}).get("value_as_string", ""),
            "last_seen": b.get("last_seen", {}).get("value_as_string", ""),
            "score": score,
            "honeypot_breakdown": hps,
            # ── enrichment ──
            "credentials": creds,
            "credential_count": cred_card,
            "top_commands": top_cmds,
            "key_implant": key_implant,
            "immutable_flag": immutable,
            "cve_probes": cve_probes,
            "malware_family": malware_fam,
            "services": services,
            "eventids": eventids,
        })

    # Rank by composite score across the full candidate set (NOT by n_vectors
    # first — that buried high-severity single-vector actors and caused the panel
    # to under-fill on long windows). Multi-vector actors still float to the top
    # because n_vectors contributes heavily to the score.
    actors.sort(key=lambda a: (a["n_vectors"], a["score"], a["max_level"], a["total_events"]), reverse=True)
    multi = [a for a in actors if a["n_vectors"] >= 2]
    return {
        "actors": actors[:limit],
        "multi_vector_count": len(multi),
        "total_actors": len(actors),
        "window_minutes": minutes,
    }


@app.route("/api/threat_actors")
@rate_limit(max_per_minute=30)
def api_threat_actors():
    """Cross-honeypot threat actor correlation — unified per-IP attack profiles."""
    try:
        minutes = max(1, min(int(request.args.get("minutes", 10080)), 129600))
    except (ValueError, TypeError):
        minutes = 10080
    try:
        limit = max(1, min(int(request.args.get("limit", 15)), 100))
    except (ValueError, TypeError):
        limit = 15
    return jsonify(get_threat_actors(minutes, limit))


# ── Cases CRUD ────────────────────────────────────────────────
def _row_to_case(row: sqlite3.Row, include_children=False, conn=None) -> Dict:
    c = {
        "id": row["id"], "title": row["title"], "severity": row["severity"],
        "status": row["status"], "assignee": row["assignee"], "src_ip": row["src_ip"],
        "playbook": row["playbook"],
        "playbook_done": json.loads(row["playbook_done"] or "[]"),
        "notes": row["notes"], "created_at": row["created_at"], "updated_at": row["updated_at"],
    }
    if include_children and conn is not None:
        alerts = conn.execute(
            "SELECT * FROM case_alerts WHERE case_id=? ORDER BY added_at ASC", (row["id"],)
        ).fetchall()
        c["alerts"] = [{
            "id": a["id"], "src_ip": a["src_ip"], "summary": a["summary"],
            "detail": json.loads(a["detail_json"] or "{}"), "added_at": a["added_at"],
        } for a in alerts]
        audit_rows = conn.execute(
            "SELECT * FROM audit_log WHERE case_id=? ORDER BY ts ASC", (row["id"],)
        ).fetchall()
        c["timeline"] = [{
            "action": x["action"], "detail": x["detail"], "actor": x["actor"], "ts": x["ts"],
        } for x in audit_rows]
    return c


@app.route("/api/cases", methods=["GET"])
@rate_limit(max_per_minute=60)
def api_cases_list():
    """List cases. Optional filters: status, severity."""
    status   = request.args.get("status")
    severity = request.args.get("severity")
    where, params = [], []
    if status in ("open", "investigating", "closed"):
        where.append("status=?"); params.append(status)
    if severity in ("low", "medium", "high", "critical"):
        where.append("severity=?"); params.append(severity)
    sql = "SELECT * FROM cases"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'investigating' THEN 1 ELSE 2 END, updated_at DESC"
    try:
        conn = get_db()
        try:
            rows = conn.execute(sql, params).fetchall()
            cases = [_row_to_case(r) for r in rows]
            counts = {"open": 0, "investigating": 0, "closed": 0}
            for r in conn.execute("SELECT status, COUNT(*) c FROM cases GROUP BY status").fetchall():
                counts[r["status"]] = r["c"]
        finally:
            conn.close()
        return jsonify({"cases": cases, "counts": counts})
    except Exception as e:
        log.error("cases list failed: %s", e)
        return jsonify({"error": "DB error", "cases": []}), 500


@app.route("/api/cases/<int:case_id>", methods=["GET"])
@rate_limit(max_per_minute=60)
def api_case_get(case_id):
    """Get one case with its alerts + audit timeline."""
    try:
        conn = get_db()
        try:
            row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                return jsonify({"error": "Not found"}), 404
            case = _row_to_case(row, include_children=True, conn=conn)
        finally:
            conn.close()
        return jsonify(case)
    except Exception as e:
        log.error("case get failed: %s", e)
        return jsonify({"error": "DB error"}), 500


@app.route("/api/cases", methods=["POST"])
@rate_limit(max_per_minute=30)
def api_case_create():
    """Create a case. Body: {title, severity, assignee, src_ip, playbook, notes, alert?}

    Optional `alert` object (the drawer context) is snapshotted into case_alerts.
    """
    data = request.get_json(force=True, silent=True) or {}
    title = str(data.get("title", "")).strip()[:200]
    if not title:
        return jsonify({"error": "title is required"}), 400
    severity = str(data.get("severity", "medium")).lower()
    if severity not in ("low", "medium", "high", "critical"):
        severity = "medium"
    assignee = str(data.get("assignee", "unassigned")).strip()[:80] or "unassigned"
    src_ip   = str(data.get("src_ip", "") or "").strip()[:45]
    playbook = str(data.get("playbook", "") or "").strip()[:60] or None
    if playbook and playbook not in PLAYBOOKS:
        playbook = None
    notes = str(data.get("notes", "") or "")[:5000]
    alert = data.get("alert") if isinstance(data.get("alert"), dict) else None

    try:
        with _db_lock:
            conn = get_db()
            try:
                cur = conn.execute(
                    "INSERT INTO cases (title, severity, status, assignee, src_ip, playbook, notes) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (title, severity, "open", assignee, src_ip or None, playbook, notes),
                )
                cid = cur.lastrowid
                audit(conn, cid, "created", f"severity={severity}, assignee={assignee}")
                if alert and src_ip:
                    summary = f"{alert.get('total_events','?')} events · max level {alert.get('max_level','?')}"
                    conn.execute(
                        "INSERT INTO case_alerts (case_id, src_ip, summary, detail_json) VALUES (?,?,?,?)",
                        (cid, src_ip, summary, json.dumps(alert)[:200000]),
                    )
                    audit(conn, cid, "alert_added", f"ip={src_ip}")
                conn.commit()
                row = conn.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
                case = _row_to_case(row, include_children=True, conn=conn)
            finally:
                conn.close()
        return jsonify(case), 201
    except Exception as e:
        log.error("case create failed: %s", e)
        return jsonify({"error": "DB error"}), 500


@app.route("/api/cases/<int:case_id>", methods=["PATCH"])
@rate_limit(max_per_minute=60)
def api_case_update(case_id):
    """Update a case. Body may include: status, severity, assignee, notes,
    playbook, playbook_done (list of step indices), append_note (string),
    add_alert (drawer context dict)."""
    data = request.get_json(force=True, silent=True) or {}
    try:
        with _db_lock:
            conn = get_db()
            try:
                row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
                if not row:
                    return jsonify({"error": "Not found"}), 404

                sets, params, changes = [], [], []

                if "status" in data and data["status"] in ("open", "investigating", "closed"):
                    if data["status"] != row["status"]:
                        sets.append("status=?"); params.append(data["status"])
                        changes.append(("status_change", f"{row['status']} → {data['status']}"))
                if "severity" in data and data["severity"] in ("low", "medium", "high", "critical"):
                    if data["severity"] != row["severity"]:
                        sets.append("severity=?"); params.append(data["severity"])
                        changes.append(("updated", f"severity → {data['severity']}"))
                if "assignee" in data:
                    a = str(data["assignee"]).strip()[:80] or "unassigned"
                    if a != row["assignee"]:
                        sets.append("assignee=?"); params.append(a)
                        changes.append(("updated", f"assignee → {a}"))
                if "notes" in data:
                    sets.append("notes=?"); params.append(str(data["notes"])[:5000])
                    changes.append(("note", "notes edited"))
                if "playbook" in data:
                    pb = str(data["playbook"] or "").strip()[:60] or None
                    if pb and pb not in PLAYBOOKS:
                        pb = None
                    sets.append("playbook=?"); params.append(pb)
                    changes.append(("updated", f"playbook → {pb or 'none'}"))
                if "playbook_done" in data and isinstance(data["playbook_done"], list):
                    done = [int(i) for i in data["playbook_done"] if isinstance(i, (int, float))][:50]
                    sets.append("playbook_done=?"); params.append(json.dumps(done))
                    changes.append(("playbook_step", f"{len(done)} steps complete"))

                append_note = str(data.get("append_note", "") or "").strip()
                if append_note:
                    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
                    new_notes = (row["notes"] + f"\n[{stamp}] {append_note}").strip()[:5000]
                    sets.append("notes=?"); params.append(new_notes)
                    changes.append(("note", append_note[:120]))

                if sets:
                    sets.append("updated_at=?"); params.append(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"))
                    params.append(case_id)
                    conn.execute(f"UPDATE cases SET {', '.join(sets)} WHERE id=?", params)

                add_alert = data.get("add_alert")
                if isinstance(add_alert, dict) and add_alert.get("ip"):
                    summary = f"{add_alert.get('total_events','?')} events · max level {add_alert.get('max_level','?')}"
                    try:
                        conn.execute(
                            "INSERT INTO case_alerts (case_id, src_ip, summary, detail_json) VALUES (?,?,?,?)",
                            (case_id, add_alert["ip"], summary, json.dumps(add_alert)[:200000]),
                        )
                        changes.append(("alert_added", f"ip={add_alert['ip']}"))
                    except sqlite3.IntegrityError:
                        pass

                for action, detail in changes:
                    audit(conn, case_id, action, detail)
                conn.commit()
                row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
                case = _row_to_case(row, include_children=True, conn=conn)
            finally:
                conn.close()
        return jsonify(case)
    except Exception as e:
        log.error("case update failed: %s", e)
        return jsonify({"error": "DB error"}), 500


@app.route("/api/cases/export")
@rate_limit(max_per_minute=12)
def api_cases_export():
    """Export all cases as CSV for reporting."""
    import csv, io
    status = request.args.get("status")
    sql = "SELECT * FROM cases"
    params = []
    if status in ("open", "investigating", "closed"):
        sql += " WHERE status=?"; params.append(status)
    sql += " ORDER BY created_at DESC"
    try:
        conn = get_db()
        try:
            rows = conn.execute(sql, params).fetchall()
            alert_counts = {}
            for r in conn.execute("SELECT case_id, COUNT(*) c FROM case_alerts GROUP BY case_id").fetchall():
                alert_counts[r["case_id"]] = r["c"]
        finally:
            conn.close()
    except Exception as e:
        log.error("cases export failed: %s", e)
        return jsonify({"error": "DB error"}), 500

    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "title", "severity", "status", "assignee", "src_ip",
                "playbook", "attached_alerts", "created_at", "updated_at", "notes"])
    for r in rows:
        w.writerow([
            r["id"], r["title"], r["severity"], r["status"], r["assignee"],
            r["src_ip"] or "", r["playbook"] or "", alert_counts.get(r["id"], 0),
            r["created_at"], r["updated_at"], (r["notes"] or "").replace("\n", " | "),
        ])
    resp = Response(out.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = "attachment; filename=soc-cases.csv"
    return resp


# ============================================================
# CLI
# ============================================================
# Optional compression — safe to skip if not installed
try:
    from flask_compress import Compress
    Compress(app)
except Exception:
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    print(f"[+] SOC Dashboard v3 on http://{args.host}:{args.port}")
    print(f"[+] Tailscale: http://100.82.166.75:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)
