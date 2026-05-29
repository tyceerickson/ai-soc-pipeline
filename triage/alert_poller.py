#!/usr/bin/env python3
import os
"""
alert_poller.py — Wazuh Alert Poller (OpenSearch backend)
=========================================================
Queries the Wazuh OpenSearch indexer for recent alerts, enriches them
with GeoIP data from the local cowrie_enriched.json lookup table, and
writes a structured JSON cache for the AI triage layer.

Part of the wazuh-soc-pipeline — Project 4
Runs on: Ubuntu Server (192.168.10.4)
Queries: OpenSearch at https://localhost:9200

Usage:
    python3 alert_poller.py
    python3 alert_poller.py --minutes 60 --min-level 7
    python3 alert_poller.py --honeypot-only --limit 25
    python3 alert_poller.py --no-save
"""

import json
import argparse
import sys
import ssl
import base64
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter

# ============================================================
# Configuration
# ============================================================
OPENSEARCH_URL  = "https://localhost:9200"
OS_USER         = "admin"
OS_PASS         = os.environ.get("OPENSEARCH_PASS", "")
ALERT_INDEX     = "wazuh-alerts-4.x-*"

# GeoIP enrichment source — built from cowrie_enriched.json
GEOIP_SOURCE    = "/opt/cowrie-logs/cowrie_enriched.json"

DEFAULT_OUTPUT       = "/opt/wazuh-soc/data/alerts_raw.json"
DEFAULT_MINUTES      = 60
DEFAULT_LEVEL        = 6
DEFAULT_LIMIT        = 100

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE

AUTH_HEADER = "Basic " + base64.b64encode(
    f"{OS_USER}:{OS_PASS}".encode()
).decode()


# ============================================================
# GeoIP lookup table
# ============================================================
def build_geoip_lookup(source_path):
    """
    Build an IP -> geo dict from cowrie_enriched.json.
    This gives us accurate GeoIP without waiting for OpenSearch
    to re-index freshly enriched events.
    """
    lookup = {}
    path = Path(source_path)
    if not path.exists():
        print(f"[!] GeoIP source not found: {source_path} — skipping enrichment",
              file=sys.stderr)
        return lookup

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                ip = e.get("src_ip")
                if ip and ip not in lookup and e.get("src_country"):
                    lookup[ip] = {
                        "country": e.get("src_country", ""),
                        "city":    e.get("src_city", ""),
                        "org":     e.get("src_org", ""),
                        "asn":     e.get("src_asn", ""),
                    }
            except (json.JSONDecodeError, KeyError):
                continue

    return lookup


# ============================================================
# OpenSearch helpers
# ============================================================
def os_request(path, body=None):
    """Make a request to OpenSearch."""
    url = f"{OPENSEARCH_URL}{path}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": AUTH_HEADER,
    }
    data   = json.dumps(body).encode() if body else None
    method = "POST" if data else "GET"
    req    = urllib.request.Request(
        url, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"[-] OpenSearch HTTP {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[-] Cannot reach OpenSearch at {OPENSEARCH_URL}: {e.reason}",
              file=sys.stderr)
        print("[-] Check: sudo systemctl status wazuh-indexer", file=sys.stderr)
        sys.exit(1)


def fetch_alerts(minutes, min_level, limit, honeypot_only=False):
    """Query OpenSearch for recent alerts."""
    since    = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    since_ms = int(since.timestamp() * 1000)

    filters = [
        {"range": {"timestamp": {"gte": since_ms}}},
        {"range": {"rule.level": {"gte": min_level}}},
    ]
    if honeypot_only:
        filters.append({"exists": {"field": "data.honeypot"}})

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters}},
        "_source": True,
    }

    return os_request(f"/{ALERT_INDEX}/_search", body=query)


# ============================================================
# Normalization
# ============================================================
def normalize_alert(hit, geoip_lookup):
    """
    Flatten an OpenSearch alert document and enrich with GeoIP.
    GeoIP comes from the local lookup table, which is more complete
    than what OpenSearch has indexed (avoids re-indexing lag).
    """
    src   = hit.get("_source", {})
    rule  = src.get("rule", {})
    agent = src.get("agent", {})
    data  = src.get("data", {})

    # GeoIP — try OpenSearch first, fall back to local lookup
    geo = data.get("location", {})
    if not isinstance(geo, dict):
        geo = {}

    src_ip = (
        data.get("src_ip") or
        data.get("srcip") or
        ""
    )

    # Enrich from local lookup if OpenSearch geo is empty
    if src_ip and not geo.get("country_name"):
        local_geo = geoip_lookup.get(src_ip, {})
        if local_geo:
            geo = {
                "country_name": local_geo.get("country", ""),
                "city_name":    local_geo.get("city", ""),
                "org":          local_geo.get("org", ""),
                "asn":          local_geo.get("asn", ""),
            }

    # Severity label
    level = rule.get("level", 0)
    if level >= 15:
        severity = "critical"
    elif level >= 12:
        severity = "high"
    elif level >= 7:
        severity = "medium"
    elif level >= 4:
        severity = "low"
    else:
        severity = "info"

    # MITRE
    mitre            = rule.get("mitre", {})
    mitre_ids        = mitre.get("id", [])
    mitre_tactics    = mitre.get("tactic", [])
    mitre_techniques = mitre.get("technique", [])

    return {
        # Identity
        "alert_id":          hit.get("_id", ""),
        "timestamp":         src.get("timestamp", ""),

        # Rule
        "rule_id":           rule.get("id", ""),
        "rule_level":        level,
        "severity":          severity,
        "rule_desc":         rule.get("description", ""),
        "rule_groups":       rule.get("groups", []),

        # Agent
        "agent_name":        agent.get("name", ""),
        "log_location":      src.get("location", ""),

        # Network / attacker — fully GeoIP enriched
        "src_ip":            src_ip,
        "src_country":       geo.get("country_name", ""),
        "src_city":          geo.get("city_name", ""),
        "src_org":           geo.get("org", ""),
        "src_asn":           geo.get("asn", ""),

        # Honeypot specifics
        "honeypot":          data.get("honeypot", ""),
        "honeypot_sensor":   data.get("honeypot_sensor", ""),
        "eventid":           data.get("eventid", ""),
        "session":           data.get("session", ""),
        "protocol":          data.get("protocol", ""),

        # Credential / command data
        "username":          data.get("username", ""),
        "password":          data.get("password", ""),
        "command":           data.get("command", "") or data.get("input", ""),

        # MITRE ATT&CK
        "mitre_ids":         mitre_ids,
        "mitre_tactics":     mitre_tactics,
        "mitre_techniques":  mitre_techniques,

        # Full log for AI context (capped)
        "full_log":          src.get("full_log", "")[:600],

        # Compliance
        "pci_dss":           rule.get("pci_dss", []),
        "nist_800_53":       rule.get("nist_800_53", []),
    }


# ============================================================
# Statistics
# ============================================================
def compute_stats(alerts):
    severities = Counter(a["severity"] for a in alerts)
    rule_ids   = Counter(a["rule_id"] for a in alerts)
    src_ips    = Counter(a["src_ip"] for a in alerts if a["src_ip"])
    countries  = Counter(a["src_country"] for a in alerts if a["src_country"])
    orgs       = Counter(a["src_org"] for a in alerts if a["src_org"])
    tactics    = Counter(t for a in alerts for t in a["mitre_tactics"])
    honeypot_n = sum(1 for a in alerts if a["honeypot"])
    eventids   = Counter(a["eventid"] for a in alerts if a["eventid"])

    # Credential summary
    creds = [
        f"{a['username']}/{a['password']}"
        for a in alerts
        if a.get("username") and a.get("password")
    ]
    top_creds = dict(Counter(creds).most_common(10))

    # Command summary
    commands = [a["command"] for a in alerts if a.get("command")]
    top_commands = dict(Counter(commands).most_common(10))

    return {
        "total":            len(alerts),
        "honeypot_alerts":  honeypot_n,
        "by_severity":      dict(severities),
        "top_rule_ids":     dict(rule_ids.most_common(10)),
        "top_src_ips":      dict(src_ips.most_common(10)),
        "top_countries":    dict(countries.most_common(10)),
        "top_orgs":         dict(orgs.most_common(5)),
        "mitre_tactics":    dict(tactics.most_common()),
        "cowrie_eventids":  dict(eventids.most_common()),
        "top_credentials":  top_creds,
        "top_commands":     top_commands,
    }


# ============================================================
# CLI
# ============================================================
def parse_args():
    parser = argparse.ArgumentParser(
        description="Poll Wazuh OpenSearch for recent alerts with GeoIP enrichment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 alert_poller.py
  python3 alert_poller.py --minutes 60 --min-level 7
  python3 alert_poller.py --honeypot-only --limit 50
  python3 alert_poller.py --no-save
        """
    )
    parser.add_argument("--minutes",       type=int,  default=DEFAULT_MINUTES)
    parser.add_argument("--min-level",     type=int,  default=DEFAULT_LEVEL)
    parser.add_argument("--limit",         type=int,  default=DEFAULT_LIMIT)
    parser.add_argument("--honeypot-only", action="store_true")
    parser.add_argument("--output",        type=str,  default=DEFAULT_OUTPUT)
    parser.add_argument("--no-save",       action="store_true")
    return parser.parse_args()


# ============================================================
# Main
# ============================================================
def main():
    args = parse_args()

    print("[+] alert_poller.py — Wazuh Alert Poller")
    print(f"[+] Source: {OPENSEARCH_URL}/{ALERT_INDEX}")
    print(f"[+] Window: last {args.minutes} min | "
          f"Min level: {args.min_level} | Limit: {args.limit}")
    if args.honeypot_only:
        print("[+] Filter: honeypot events only")
    print()

    # Build GeoIP lookup
    print(f"[+] Loading GeoIP lookup from {GEOIP_SOURCE}...")
    geoip_lookup = build_geoip_lookup(GEOIP_SOURCE)
    print(f"[+] GeoIP lookup: {len(geoip_lookup)} unique IPs")

    # Query OpenSearch
    print("[+] Querying OpenSearch...")
    response  = fetch_alerts(args.minutes, args.min_level, args.limit,
                             args.honeypot_only)
    hits      = response.get("hits", {}).get("hits", [])
    total_val = response.get("hits", {}).get("total", {}).get("value", 0)
    relation  = response.get("hits", {}).get("total", {}).get("relation", "eq")
    total_str = f"{total_val}{'+ (capped)' if relation == 'gte' else ''}"

    print(f"[+] Total matching: {total_str} | Retrieved: {len(hits)}")

    if not hits:
        print("[!] No alerts found — try --minutes or --min-level adjustments")
        sys.exit(0)

    # Normalize + enrich
    print("[+] Normalizing and enriching alerts...")
    alerts = [normalize_alert(h, geoip_lookup) for h in hits]

    # Count how many got GeoIP
    geo_enriched = sum(1 for a in alerts if a["src_country"])
    print(f"[+] GeoIP enriched: {geo_enriched}/{len(alerts)} alerts")

    # Stats
    stats = compute_stats(alerts)

    print(f"\n[+] Summary:")
    print(f"    Total:           {stats['total']}")
    print(f"    Honeypot alerts: {stats['honeypot_alerts']}")
    print(f"    By severity:     {stats['by_severity']}")

    if stats["top_countries"]:
        countries_str = ", ".join(
            f"{c}({n})" for c, n in list(stats["top_countries"].items())[:5]
        )
        print(f"    Top countries:   {countries_str}")

    if stats["top_orgs"]:
        orgs_str = ", ".join(
            f"{o}({n})" for o, n in list(stats["top_orgs"].items())[:3]
        )
        print(f"    Top orgs:        {orgs_str}")

    if stats["mitre_tactics"]:
        tactics_str = ", ".join(
            f"{t}({c})"
            for t, c in list(stats["mitre_tactics"].items())[:4]
        )
        print(f"    MITRE tactics:   {tactics_str}")

    if stats["top_src_ips"]:
        top_ip = list(stats["top_src_ips"].items())[0]
        print(f"    Top attacker:    {top_ip[0]} ({top_ip[1]} alerts)")

    if stats["top_credentials"]:
        top_cred = list(stats["top_credentials"].items())[0]
        print(f"    Top credential:  {top_cred[0]} ({top_cred[1]}x)")

    if stats["top_commands"]:
        top_cmd = list(stats["top_commands"].items())[0]
        cmd_preview = top_cmd[0][:60] + "..." if len(top_cmd[0]) > 60 else top_cmd[0]
        print(f"    Top command:     {cmd_preview}")

    # Build output
    output = {
        "polled_at":       datetime.now(timezone.utc).isoformat(),
        "window_minutes":  args.minutes,
        "min_level":       args.min_level,
        "honeypot_only":   args.honeypot_only,
        "total_available": total_val,
        "geoip_enriched":  geo_enriched,
        "stats":           stats,
        "alerts":          alerts,
    }

    if args.no_save:
        print(json.dumps(output, indent=2))
    else:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(output, f, indent=2)
        size = out_path.stat().st_size
        print(f"\n[+] Saved {len(alerts)} alerts → {out_path} ({size:,} bytes)")

    print("[+] Done.")


if __name__ == "__main__":
    main()
