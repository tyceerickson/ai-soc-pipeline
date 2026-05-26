#!/usr/bin/env python3
"""
app.py — AI-Powered SOC Dashboard (v3)
Flask web application serving the SOC dashboard.
Runs on: Ubuntu Server (192.168.10.4)
Access via Tailscale: http://100.82.166.75:5000
"""

import json
import subprocess
import threading
import ssl
import base64
import urllib.request
import urllib.error
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ============================================================
# Configuration
# ============================================================
OPENSEARCH_URL = "https://localhost:9200"
OS_USER        = "admin"
OS_PASS        = "BJ6xeV2bh?NgSvSPPWBwU+IqRzD6HmJj"
ALERT_INDEX    = "wazuh-alerts-4.x-*"
GEOIP_SOURCE   = "/opt/cowrie-logs/cowrie_enriched.json"
TRIAGE_REPORT  = "/opt/wazuh-soc/data/triage_report.json"
ALERTS_RAW     = "/opt/wazuh-soc/data/alerts_raw.json"
PYTHON         = "/usr/bin/python3"
ENRICH_SCRIPT  = "/opt/cowrie-tools/pipeline/enrich_logs.py"
EXPORT_SCRIPT  = "/opt/cowrie-tools/pipeline/export_to_wazuh.py"
POLLER_SCRIPT  = "/opt/wazuh-soc/triage/alert_poller.py"
TRIAGE_SCRIPT  = "/opt/wazuh-soc/triage/ai_triage.py"
LOG_DIR        = "/opt/wazuh-soc/logs"

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE
AUTH_HEADER = "Basic " + base64.b64encode(
    f"{OS_USER}:{OS_PASS}".encode()
).decode()

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
def os_query(path, body=None):
    url     = f"{OPENSEARCH_URL}{path}"
    headers = {"Content-Type": "application/json", "Authorization": AUTH_HEADER}
    data    = json.dumps(body).encode() if body else None
    method  = "POST" if data else "GET"
    req     = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# GeoIP lookup
# ============================================================
def build_geoip_lookup():
    cache_path = "/opt/cowrie-logs/geoip_cache.json"
    try:
        with open(cache_path) as f:
            return json.load(f)
    except Exception:
        pass
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
        i_type, i_val, interval = "fixed_interval",    "5m",  "5m"
    elif minutes <= 720:
        i_type, i_val, interval = "fixed_interval",    "30m", "30m"
    elif minutes <= 1440:
        i_type, i_val, interval = "fixed_interval",    "2h",  "2h"
    elif minutes <= 10080:
        i_type, i_val, interval = "fixed_interval",    "12h", "12h"
    elif minutes <= 43200:
        i_type, i_val, interval = "calendar_interval", "day", "1d"
    else:
        i_type, i_val, interval = "calendar_interval", "week","1w"

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


def build_mitre_panel(minutes, since_ms, tactics, techniques, ids):
    tactic_map = {
        "Discovery":            ["T1046"],
        "Credential Access":    ["T1110", "T1110.001"],
        "Persistence":          ["T1098.004", "T1098"],
        "Execution":            ["T1059"],
        "Defense Evasion":      ["T1078"],
        "Initial Access":       ["T1078"],
        "Privilege Escalation": ["T1078"],
    }
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
            {"name": "Session Connect",    "count": aggs.get("connect",       {}).get("doc_count", 0), "color": "#388bfd"},
            {"name": "SSH Key Exchange",   "count": aggs.get("client_kex",    {}).get("doc_count", 0), "color": "#a371f7"},
            {"name": "Login Failed",       "count": aggs.get("login_failed",  {}).get("doc_count", 0), "color": "#f85149"},
            {"name": "Login Success",      "count": aggs.get("login_success", {}).get("doc_count", 0), "color": "#d29922"},
            {"name": "Command Executed",   "count": aggs.get("cmd_input",     {}).get("doc_count", 0), "color": "#f0883e"},
            {"name": "File Downloaded",    "count": aggs.get("file_download", {}).get("doc_count", 0), "color": "#ff79c6"},
            {"name": "File Uploaded",      "count": aggs.get("file_upload",   {}).get("doc_count", 0), "color": "#3fb950"},
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
        "size": 500,
        "query": {"bool": {"filter": [
            {"range": {"data.timestamp": {"gte": since.isoformat()}}},
            {"exists": {"field": "data.honeypot"}},
            {"terms": {"data.session": top_session_ids[:10]}},
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
def get_botnets(minutes):
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    # Known botnet signatures
    BOTNETS = [
        {"name": "mdrfckr Botnet",    "color": "#f85149", "sig": "mdrfckr",          "field": "data.input"},
        {"name": "345gs5662d34",       "color": "#f0883e", "sig": "345gs5662d34",     "field": "data.password"},
        {"name": "Solana Scanner",     "color": "#d29922", "sig": "solana",           "field": "data.username"},
        {"name": "Admin Brute Force",  "color": "#a371f7", "sig": "admin",            "field": "data.username"},
        {"name": "Root Brute Force",   "color": "#ff79c6", "sig": "root",             "field": "data.username"},
        {"name": "Telnet Scanner",     "color": "#388bfd", "sig": "cowrie.telnet",    "field": "data.protocol"},
    ]

    results = []
    for bot in BOTNETS:
        if bot["field"] == "data.protocol":
            q = {"term": {"data.protocol": "telnet"}}
        else:
            q = {"wildcard": {bot["field"]: f"*{bot['sig']}*"}}

        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"data.timestamp": {"gte": since.isoformat()}}},
                {"exists": {"field": "data.honeypot"}},
                q,
            ]}},
            "aggs": {
                "unique_ips": {"cardinality": {"field": "data.src_ip"}},
                "timeline": {
                    "date_histogram": {
                        "field": "data.timestamp",
                        "fixed_interval": "2h",
                        "min_doc_count": 0,
                        "extended_bounds": {
                            "min": since.isoformat(),
                            "max": datetime.now(timezone.utc).isoformat()
                        }
                    }
                }
            }
        }
        result = os_query(f"/{ALERT_INDEX}/_search", body)
        count = result.get("hits", {}).get("total", {}).get("value", 0)
        unique_ips = result.get("aggregations", {}).get("unique_ips", {}).get("value", 0)
        tl = [{"ts": b["key"], "count": b["doc_count"]}
              for b in result.get("aggregations", {}).get("timeline", {}).get("buckets", [])]
        if count > 0:
            results.append({
                "name":       bot["name"],
                "color":      bot["color"],
                "count":      count,
                "unique_ips": unique_ips,
                "timeline":   tl,
            })

    return {"botnets": sorted(results, key=lambda x: x["count"], reverse=True)}


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
    steps = [
        ("Enriching logs with GeoIP...", [PYTHON, ENRICH_SCRIPT]),
        ("Exporting to Wazuh format...", [PYTHON, EXPORT_SCRIPT,
          "--input", "/opt/cowrie-logs/cowrie_enriched.json",
          "--output-dir", "/opt/cowrie-logs/wazuh/",
          "--wazuh-manager", "127.0.0.1"]),
    ]
    for msg, cmd in steps:
        refresh_state["progress"] = msg
        try:
            subprocess.run(cmd, timeout=180, capture_output=True)
        except Exception as e:
            refresh_state["error"] = str(e)
            refresh_state["running"] = False
            return
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
    OLLAMA_URL = "http://100.72.171.104:11434/api/generate"

    # Get sample events for this botnet to give AI real context
    BOTNET_QUERIES = {
        "mdrfckr Botnet":   {"term": {"data.input": "mdrfckr"}},
        "345gs5662d34":     {"term": {"data.password": "3245gs5662d34"}},
        "Solana Scanner":   {"term": {"data.username": "solana"}},
        "Admin Brute Force":{"term": {"data.username": "admin"}},
        "Root Brute Force": {"term": {"data.username": "root"}},
        "Telnet Scanner":   {"term": {"data.protocol": "telnet"}},
    }

    query = BOTNET_QUERIES.get(name, {"term": {"data.honeypot": "cowrie-raw"}})
    sample_body = {
        "size": 5,
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

    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        body = json.dumps({
            "model": "llama3.1:8b",
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3},
        }).encode()
        req = urllib.request.Request(
            OLLAMA_URL, data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            result = json.loads(r.read().decode())
        raw = result.get("response", "")
        # Clean JSON
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"): raw = raw[4:]
        return json.loads(raw.strip())
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# Routes
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def api_stats():
    minutes = int(request.args.get("minutes", 60))
    return jsonify(get_live_stats(minutes))

@app.route("/api/attack_chain")
def api_attack_chain():
    minutes = int(request.args.get("minutes", 1440))
    return jsonify(get_attack_chain(minutes))

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
def api_botnets():
    minutes = int(request.args.get("minutes", 10080))
    return jsonify(get_botnets(minutes))

@app.route("/api/botnet_analysis", methods=["POST"])
def api_botnet_analysis():
    data       = request.get_json() or {}
    name       = data.get("name", "Unknown")
    count      = int(data.get("count", 0))
    unique_ips = int(data.get("unique_ips", 0))
    result     = analyze_botnet_with_ai(name, count, unique_ips)
    return jsonify(result)


@app.route("/api/cred_intel")
def api_cred_intel():
    minutes = int(request.args.get("minutes", 10080))
    return jsonify(get_credential_intel(minutes))

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
    global analysis_state
    if analysis_state["running"]:
        return jsonify({"error": "Analysis already running"}), 409
    data    = request.get_json() or {}
    mode    = data.get("mode", "summary")
    minutes = max(1,  min(int(data.get("minutes", 60)),  129600))
    limit   = max(10, min(int(data.get("limit",   100)), 500))
    if mode not in ("summary", "full", "executive"):
        return jsonify({"error": "Invalid mode"}), 400
    threading.Thread(target=run_analysis_thread, args=(mode, minutes, limit), daemon=True).start()
    return jsonify({"status": "started", "mode": mode, "minutes": minutes, "limit": limit})

@app.route("/api/analysis/status")
def api_analysis_status():
    return jsonify(analysis_state)


# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    print(f"[+] SOC Dashboard v3 on http://{args.host}:{args.port}")
    print(f"[+] Tailscale: http://100.82.166.75:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)
