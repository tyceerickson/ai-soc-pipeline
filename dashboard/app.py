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
from flask import Flask, jsonify, render_template, request

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
OS_PASS        = os.environ.get("OPENSEARCH_PASS", "BJ6xeV2bh?NgSvSPPWBwU+IqRzD6HmJj")
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

# ── Startup config validation ─────────────────────────────────
for _script in [ENRICH_SCRIPT, TRIAGE_SCRIPT]:
    if not Path(_script).exists():
        log.warning("Script not found: %s — some features may be unavailable", _script)
for _dir in [LOG_DIR, str(Path(TRIAGE_REPORT).parent)]:
    try:
        Path(_dir).mkdir(parents=True, exist_ok=True)
    except Exception as _e:
        log.warning("Cannot create dir %s: %s", _dir, _e)

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
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as r:
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
                    "size":  100,
                    "order": {"_count": "desc"},
                    "min_doc_count": 2,
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
        for k, v in sorted(cmds.items(), key=lambda x: x[1], reverse=True)[:100]
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

    countries = {}
    for b in aggs.get("by_country", {}).get("buckets", []):
        k = b["key"]
        if k and k != "Unknown":
            countries[k] = b["doc_count"]

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
    # Find sessions with login.success OR command.input OR file_download (interesting sessions)
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since.isoformat()}}},
            {"exists": {"field": "data.honeypot"}},
            {"exists": {"field": "data.session"}},
            {"bool": {"should": [
                {"term": {"data.eventid": "cowrie.login.success"}},
                {"term": {"data.eventid": "cowrie.command.input"}},
                {"term": {"data.eventid": "cowrie.session.file_download"}},
            ], "minimum_should_match": 1}},
        ]}},
        "aggs": {
            "top_sessions": {
                "terms": {"field": "data.session", "size": 30, "order": {"_count": "desc"}}
            }
        }
    }
    result = os_query(f"/{ALERT_INDEX}/_search", body)
    top_session_ids = [b["key"] for b in result.get("aggregations", {}).get("top_sessions", {}).get("buckets", [])]

    if not top_session_ids:
        return {"sessions": []}

    # Fetch events for top sessions
    body2 = {
        "size": 1000,
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since.isoformat()}}},
            {"exists": {"field": "data.honeypot"}},
            {"terms": {"data.session": top_session_ids[:20]}},
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
                    "size": 50,
                    "min_doc_count": 10,
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
        # Name the campaign from the credential
        if len(pwd) > 4 and (pwd == user or any(c.isdigit() for c in pwd)):
            name = f"{pwd[:20]} Campaign"
        elif len(user) > 3 and user not in ("root","admin","user","test"):
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
        # Deduplicate using Levenshtein distance for similar credentials
        # This catches variants like "345gs5662d34" vs "3245gs5662d34" (edit distance = 1)
        is_dupe = False
        for existing in campaigns:
            ev = existing.get("_sig_val", "")
            eu = existing.get("_sig_user", "")
            if not ev:
                continue
            # Fast path: direct substring containment
            shorter = min(pwd, ev, key=len)
            longer  = max(pwd, ev, key=len)
            if len(shorter) > 5 and shorter in longer:
                is_dupe = True
            # Levenshtein distance <= 2 for passwords longer than 6 chars
            elif len(pwd) > 6 and len(ev) > 6:
                dist = _levenshtein(pwd, ev)
                if dist <= 2:
                    is_dupe = True
            # Same username, similar password length (same family)
            elif eu and eu == user and abs(len(pwd) - len(ev)) < 3:
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
    seen_cmd_sigs = set()
    for b in cmd_result.get("aggregations", {}).get("top_cmds", {}).get("buckets", []):
        cmd   = b["key"]
        count = b["doc_count"]
        n_ips = b.get("unique_ips", {}).get("value", 0)
        if n_ips < 3 or len(cmd) < 5:
            continue
        # Extract a short signature from the command
        words = cmd.split()
        sig = words[0] if words else cmd[:20]
        if sig in seen_cmd_sigs:
            continue
        seen_cmd_sigs.add(sig)
        # Name by what the command does
        if "ssh-rsa" in cmd or "authorized_keys" in cmd:
            name = "SSH Key Implant"
        elif "chattr" in cmd:
            name = "Anti-Forensic (chattr)"
        elif "wget" in cmd or "curl" in cmd:
            name = "Downloader Campaign"
        elif "uname" in cmd or "cat /proc" in cmd or "lscpu" in cmd:
            name = "System Recon Campaign"
        elif "busybox" in cmd:
            name = "BusyBox IoT Scanner"
        elif "chmod" in cmd and "setup" in cmd:
            name = "Dropper Campaign"
        else:
            name = f"{sig[:20]} Campaign"
        # Filter out generic Linux commands that aren't campaign signatures
        GENERIC_CMDS = {
            'echo','cat','ls','rm','df','free','ps','id','pwd','env','top',
            'who','w','last','uptime','date','hostname','uname','whoami',
            'ifconfig','ip','netstat','ss','lscpu','lsblk','mount','find',
            'grep','awk','sed','head','tail','wc','sort','uniq','cut','tr',
            'crontab','which','whereis','history','export','set','alias',
            'cd','mkdir','touch','cp','mv','chmod','chown','ln','stat',
        }
        # Only skip if it's a generic command AND not a named campaign type
        is_named = name not in [f"{sig[:20]} Campaign"]
        if sig.lower() in GENERIC_CMDS and not is_named:
            continue
        # Filter out HTTP/protocol noise
        if any(x in sig for x in ['Host:', 'GET ', 'POST ', 'HTTP/', 'User-Agent',
                                    'Content-', 'Accept', 'Mozilla', '174.138']):
            continue
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
            # Binaries captured
            "binaries": {
                "filter": {"term": {"data.eventid": "dionaea.binary.captured"}},
                "aggs": {
                    "hashes": {"terms": {"field": "data.sha256", "size": 20}},
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

    # Malware binaries
    binaries = []
    for b in aggs.get("binaries", {}).get("hashes", {}).get("buckets", []):
        binaries.append({
            "sha256":    b["key"],
            "count":     b["doc_count"],
            "sha256_short": b["key"][:16] + "…",
        })

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
            with urllib.request.urlopen(req, timeout=120) as r:
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
