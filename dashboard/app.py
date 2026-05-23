#!/usr/bin/env python3
"""
app.py — AI-Powered SOC Dashboard (v2)
=======================================
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

# Global state for background jobs
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
# Live stats query
# ============================================================
def get_live_stats(minutes=60):
    since    = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    since_ms = int(since.timestamp() * 1000)

    # Timeline interval — fixed_interval only supports ms/s/m/h/d
    # calendar_interval used for day/week to avoid OpenSearch errors
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
            # Severity breakdown using range on rule.level
            "severity_critical": {"filter": {"range": {"rule.level": {"gte": 15}}}},
            "severity_high":     {"filter": {"range": {"rule.level": {"gte": 12, "lt": 15}}}},
            "severity_medium":   {"filter": {"range": {"rule.level": {"gte": 7,  "lt": 12}}}},
            "severity_low":      {"filter": {"range": {"rule.level": {"gte": 0,  "lt": 7}}}},

            # Timeline with severity breakdown
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
                    "high":     {"filter": {"range": {"rule.level": {"gte": 12}}}},
                    "medium":   {"filter": {"range": {"rule.level": {"gte": 7, "lt": 12}}}},
                    "low":      {"filter": {"range": {"rule.level": {"gte": 0, "lt": 7}}}},
                }
            },

            # Countries
            "by_country": {
                "terms": {
                    "field": "data.location.country_name",
                    "size":  15,
                    "missing": "Unknown",
                }
            },

            # Source IPs
            "by_src_ip": {
                "terms": {"field": "data.src_ip", "size": 15}
            },

            # Event types
            "by_eventid": {
                "terms": {"field": "data.eventid", "size": 15}
            },

            # MITRE tactics
            "mitre_tactics": {
                "terms": {"field": "rule.mitre.tactic", "size": 20}
            },

            # MITRE techniques
            "mitre_techniques": {
                "terms": {"field": "rule.mitre.technique", "size": 20}
            },

            # MITRE IDs
            "mitre_ids": {
                "terms": {"field": "rule.mitre.id", "size": 20}
            },
        }
    }

    result = os_query(f"/{ALERT_INDEX}/_search", body)
    if "error" in result:
        return {"error": result["error"]}

    hits = result.get("hits", {})
    aggs = result.get("aggregations", {})
    total = hits.get("total", {}).get("value", 0)

    # Severity counts
    severity = {
        "critical": aggs.get("severity_critical", {}).get("doc_count", 0),
        "high":     aggs.get("severity_high",     {}).get("doc_count", 0),
        "medium":   aggs.get("severity_medium",   {}).get("doc_count", 0),
        "low":      aggs.get("severity_low",      {}).get("doc_count", 0),
    }

    # Timeline with per-severity breakdown
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

    # Countries
    countries = {}
    for b in aggs.get("by_country", {}).get("buckets", []):
        k = b["key"]
        if k and k != "Unknown":
            countries[k] = b["doc_count"]

    # If OpenSearch countries empty fall back to alerts_raw
    if not countries:
        try:
            with open(ALERTS_RAW) as f:
                raw = json.load(f)
            countries = raw.get("stats", {}).get("top_countries", {})
        except Exception:
            pass

    # Event types — simplify cowrie prefix
    event_types = {}
    for b in aggs.get("by_eventid", {}).get("buckets", []):
        k = b["key"].replace("cowrie.", "").replace(".", " ")
        event_types[k] = b["doc_count"]

    # Source IPs with GeoIP enrichment
    geo_lookup = build_geoip_lookup()
    top_ips = []
    for b in aggs.get("by_src_ip", {}).get("buckets", []):
        ip  = b["key"]
        geo = geo_lookup.get(ip, {})
        top_ips.append({
            "ip":      ip,
            "count":   b["doc_count"],
            "country": geo.get("country", ""),
            "org":     geo.get("org", ""),
        })

    # MITRE data
    mitre_tactics = {}
    for b in aggs.get("mitre_tactics", {}).get("buckets", []):
        mitre_tactics[b["key"]] = b["doc_count"]

    mitre_techniques = {}
    for b in aggs.get("mitre_techniques", {}).get("buckets", []):
        mitre_techniques[b["key"]] = b["doc_count"]

    mitre_ids = {}
    for b in aggs.get("mitre_ids", {}).get("buckets", []):
        mitre_ids[b["key"]] = b["doc_count"]

    # Build MITRE panel data: tactic → techniques + IDs + example alerts
    mitre_panel = build_mitre_panel(minutes, since_ms, mitre_tactics,
                                    mitre_techniques, mitre_ids)

    # Enriched stats from alerts_raw
    enriched_stats = {}
    try:
        with open(ALERTS_RAW) as f:
            raw = json.load(f)
        enriched_stats = raw.get("stats", {})
    except Exception:
        pass

    return {
        "total":           total,
        "severity":        severity,
        "countries":       countries,
        "event_types":     event_types,
        "top_ips":         top_ips,
        "timeline":        timeline,
        "timeline_interval": interval,
        "mitre_tactics":   mitre_tactics,
        "mitre_techniques":mitre_techniques,
        "mitre_ids":       mitre_ids,
        "mitre_panel":     mitre_panel,
        "enriched_stats":  enriched_stats,
        "window_minutes":  minutes,
        "as_of":           datetime.now(timezone.utc).isoformat(),
    }


def build_mitre_panel(minutes, since_ms, tactics, techniques, ids):
    """
    For each MITRE tactic, fetch up to 3 example alerts to show in the dropdown.
    Returns list of tactic objects with examples.
    """
    # Map tactic → technique IDs
    tactic_map = {
        "Discovery":         ["T1046"],
        "Credential Access": ["T1110", "T1110.001"],
        "Persistence":       ["T1098.004", "T1098"],
        "Execution":         ["T1059"],
        "Defense Evasion":   ["T1078"],
        "Initial Access":    ["T1078"],
        "Privilege Escalation": ["T1078"],
    }

    panel = []
    for tactic, count in sorted(tactics.items(), key=lambda x: x[1], reverse=True):
        # Get example alerts for this tactic
        body = {
            "size": 3,
            "query": {
                "bool": {"filter": [
                    {"range": {"data.timestamp": {"gte": datetime.fromtimestamp(since_ms/1000, tz=timezone.utc).isoformat()}}},
                    {"exists": {"field": "data.honeypot"}},
                    {"term":  {"rule.mitre.tactic": tactic}},
                ]}
            },
            "sort": [{"rule.level": "desc"}, {"timestamp": "desc"}],
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

        # Find technique IDs for this tactic
        tactic_ids = tactic_map.get(tactic, [])

        panel.append({
            "tactic":     tactic,
            "count":      count,
            "tactic_ids": tactic_ids,
            "examples":   examples,
        })

    return panel


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
    """Manual data refresh — enrich + export only, no AI."""
    global refresh_state
    refresh_state.update({
        "running": True, "error": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
    })

    steps = [
        ("Enriching logs with GeoIP...",
         [PYTHON, ENRICH_SCRIPT]),
        ("Exporting to Wazuh format...",
         [PYTHON, EXPORT_SCRIPT,
          "--input",       "/opt/cowrie-logs/cowrie_enriched.json",
          "--output-dir",  "/opt/cowrie-logs/wazuh/",
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
    """Full AI analysis pipeline."""
    global analysis_state
    analysis_state.update({
        "running": True, "error": None, "step": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
    })

    # Step 1: Enrich
    analysis_state.update({"progress": "Step 1/4: Enriching logs...", "step": 1})
    try:
        subprocess.run([PYTHON, ENRICH_SCRIPT], timeout=180, capture_output=True)
    except Exception:
        pass

    # Step 2: Export
    analysis_state.update({"progress": "Step 2/4: Exporting to Wazuh format...", "step": 2})
    try:
        subprocess.run([
            PYTHON, EXPORT_SCRIPT,
            "--input",       "/opt/cowrie-logs/cowrie_enriched.json",
            "--output-dir",  "/opt/cowrie-logs/wazuh/",
            "--wazuh-manager", "127.0.0.1",
        ], timeout=180, capture_output=True)
    except Exception:
        pass

    # Step 3: Poll
    analysis_state.update({"progress": "Step 3/4: Polling alerts from OpenSearch...", "step": 3})
    try:
        result = subprocess.run([
            PYTHON, POLLER_SCRIPT,
            "--minutes",   str(minutes),
            "--min-level", "6",
            "--limit",     str(limit),
            "--honeypot-only",
            "--output",    ALERTS_RAW,
        ], timeout=120, capture_output=True)
        if result.returncode != 0:
            analysis_state["error"] = "Poll step failed"
            analysis_state["running"] = False
            return
    except Exception as e:
        analysis_state["error"] = str(e)
        analysis_state["running"] = False
        return

    # Step 4: AI triage
    analysis_state.update({
        "progress": f"Step 4/4: Running AI analysis ({mode})...",
        "step": 4,
    })
    try:
        result = subprocess.run([
            PYTHON, TRIAGE_SCRIPT,
            "--mode",   mode,
            "--input",  ALERTS_RAW,
            "--output", TRIAGE_REPORT,
        ], timeout=600, capture_output=True, text=True)
        if result.returncode != 0:
            analysis_state["error"] = (result.stderr or "")[-300:]
    except subprocess.TimeoutExpired:
        analysis_state["error"] = "Analysis timed out (>10 min) — try Summary mode"
    except Exception as e:
        analysis_state["error"] = str(e)

    analysis_state["running"]  = False
    analysis_state["progress"] = "Complete"


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
    threading.Thread(
        target=run_analysis_thread, args=(mode, minutes, limit), daemon=True
    ).start()
    return jsonify({"status": "started", "mode": mode, "minutes": minutes, "limit": limit})


@app.route("/api/analysis/status")
def api_analysis_status():
    return jsonify(analysis_state)


# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    print(f"[+] SOC Dashboard v2 on http://{args.host}:{args.port}")
    print(f"[+] Tailscale: http://100.82.166.75:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)
