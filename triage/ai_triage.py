#!/usr/bin/env python3
"""
ai_triage.py — AI-Powered Alert Triage Layer
=============================================
Reads normalized alerts from alert_poller.py output, sends them to
Ollama (llama3.1:8b on Alienware RTX 4070) for analysis, and writes
structured triage reports with plain-English explanations.

Part of the wazuh-soc-pipeline — Project 4
Runs on:    Ubuntu Server (192.168.10.4)
LLM target: http://100.72.171.104:11434 (Alienware via Tailscale)

Usage:
    python3 ai_triage.py
    python3 ai_triage.py --input /opt/wazuh-soc/data/alerts_raw.json
    python3 ai_triage.py --mode summary
    python3 ai_triage.py --mode full
    python3 ai_triage.py --mode executive
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

# OpenSearch connection for pre-aggregation
OPENSEARCH_URL  = "https://localhost:9200"
OS_USER         = "admin"
OS_PASS         = "BJ6xeV2bh?NgSvSPPWBwU+IqRzD6HmJj"
ALERT_INDEX     = "wazuh-alerts-4.x-*"
GEOIP_CACHE     = "/opt/cowrie-logs/geoip_cache.json"

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE
_AUTH = "Basic " + base64.b64encode(
    f"{OS_USER}:{OS_PASS}".encode()
).decode()

def os_query(body):
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        f"{OPENSEARCH_URL}/{ALERT_INDEX}/_search",
        data=data,
        headers={"Content-Type": "application/json", "Authorization": _AUTH},
        method="POST"
    )
    with urllib.request.urlopen(req, context=_SSL_CTX, timeout=20) as r:
        return json.loads(r.read().decode())

def build_intelligence_summary(minutes=10080):
    """
    Query OpenSearch directly to build a rich intelligence summary
    for the LLM. Gets aggregated statistics across ALL alerts in the
    window — not just the sampled 500 — plus the most interesting
    individual events.
    """
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()

    # Load GeoIP cache
    try:
        with open(GEOIP_CACHE) as f:
            geo = json.load(f)
    except Exception:
        geo = {}

    def enrich_ip(ip):
        g = geo.get(ip, {})
        if isinstance(g, dict):
            country = g.get("country", "")
            org     = g.get("org", "")
            if country and org:
                return f"{ip} ({country}, {org})"
            elif country:
                return f"{ip} ({country})"
        return ip

    # Big aggregation query
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range":  {"data.timestamp": {"gte": since}}},
            {"exists": {"field": "data.honeypot"}},
        ]}},
        "aggs": {
            "total":          {"value_count": {"field": "data.src_ip"}},
            "by_severity_high":   {"filter": {"range": {"rule.level": {"gte": 12}}}},
            "by_severity_med":    {"filter": {"range": {"rule.level": {"gte": 7, "lt": 12}}}},
            "login_success":      {"filter": {"term": {"data.eventid": "cowrie.login.success"}}},
            "login_failed":       {"filter": {"term": {"data.eventid": "cowrie.login.failed"}}},
            "cmd_input":          {"filter": {"term": {"data.eventid": "cowrie.command.input"}}},
            "file_download":      {"filter": {"term": {"data.eventid": "cowrie.session.file_download"}}},
            "top_ips":       {"terms": {"field": "data.src_ip",               "size": 20, "order": {"_count": "desc"}}},
            "top_eventids":  {"terms": {"field": "data.eventid",              "size": 15}},
            "mitre_tactics": {"terms": {"field": "rule.mitre.tactic",         "size": 10}},
            "mitre_ids":     {"terms": {"field": "rule.mitre.id",             "size": 15}},
            "top_creds":     {"terms": {
                "script": {
                    "lang": "painless",
                    "source": "doc[\'data.username\'].size() > 0 && doc[\'data.password\'].size() > 0 ? doc[\'data.username\'].value + \'/\' + doc[\'data.password\'].value : null"
                },
                "size": 20,
                "order": {"_count": "desc"},
                "min_doc_count": 1
            }},
            "top_cmds":      {"terms": {"field": "data.input", "size": 20, "order": {"_count": "desc"}}},
            "top_sessions":  {"terms": {"field": "data.session", "size": 5,  "order": {"_count": "desc"}}},
        }
    }

    result = os_query(body)
    aggs   = result.get("aggregations", {})
    total  = aggs.get("total", {}).get("value", 0)

    # Top IPs with GeoIP
    top_ips = []
    for b in aggs.get("top_ips", {}).get("buckets", []):
        top_ips.append(f"{enrich_ip(b['key'])} — {b['doc_count']:,} alerts")

    # Credentials
    top_creds = []
    junk = ['GET ', 'POST ', 'HTTP/', 'USER ', 'Mozilla']
    for b in aggs.get("top_creds", {}).get("buckets", []):
        if not any(p in b["key"] for p in junk) and len(b["key"]) < 80:
            top_creds.append(f"{b['key']} ({b['doc_count']:,}x)")

    # Commands
    top_cmds = [
        f"{b['key'][:120]} ({b['doc_count']:,}x)"
        for b in aggs.get("top_cmds", {}).get("buckets", [])
    ]

    # MITRE
    tactics = {b["key"]: b["doc_count"] for b in aggs.get("mitre_tactics", {}).get("buckets", [])}
    mitre_ids = [b["key"] for b in aggs.get("mitre_ids", {}).get("buckets", [])]

    # Now get the 20 most interesting individual events
    # Prioritize: high severity > login.success > command.input > file_download
    interesting_body = {
        "size": 20,
        "query": {"bool": {"filter": [
            {"range":  {"data.timestamp": {"gte": since}}},
            {"exists": {"field": "data.honeypot"}},
            {"bool": {"should": [
                {"range": {"rule.level": {"gte": 10}}},
                {"terms": {"data.eventid": [
                    "cowrie.login.success",
                    "cowrie.command.input",
                    "cowrie.session.file_download",
                    "cowrie.session.file_upload",
                ]}},
            ], "minimum_should_match": 1}},
        ]}},
        "sort": [{"rule.level": "desc"}, {"data.timestamp": "desc"}],
        "_source": ["data", "rule", "timestamp"],
    }
    interesting = os_query(interesting_body)
    notable_events = []
    for h in interesting.get("hits", {}).get("hits", []):
        src  = h.get("_source", {})
        data = src.get("data", {})
        rule = src.get("rule", {})
        ip   = data.get("src_ip", "")
        event = {
            "eventid":  data.get("eventid", ""),
            "level":    rule.get("level", 0),
            "rule":     rule.get("description", ""),
            "src":      enrich_ip(ip) if ip else "",
            "cred":     f"{data.get('username','')}/{data.get('password','')}" if data.get("username") and data.get("password") else "",
            "command":  (data.get("command","") or data.get("input",""))[:150],
            "mitre":    rule.get("mitre", {}).get("id", []),
            "ts":       src.get("timestamp","")[:19],
        }
        notable_events.append(event)

    summary = {
        "window_minutes":    minutes,
        "total_events":      total,
        "high_severity":     aggs.get("by_severity_high", {}).get("doc_count", 0),
        "medium_severity":   aggs.get("by_severity_med",  {}).get("doc_count", 0),
        "login_success":     aggs.get("login_success",    {}).get("doc_count", 0),
        "login_failed":      aggs.get("login_failed",     {}).get("doc_count", 0),
        "commands_executed": aggs.get("cmd_input",        {}).get("doc_count", 0),
        "files_downloaded":  aggs.get("file_download",    {}).get("doc_count", 0),
        "top_attacker_ips":  top_ips,
        "top_credentials":   top_creds,
        "top_commands":      top_cmds,
        "mitre_tactics":     tactics,
        "mitre_technique_ids": mitre_ids,
        "notable_events":    notable_events,
    }
    return summary

# ============================================================
# Configuration
# ============================================================
OLLAMA_URL   = "http://100.72.171.104:11434"
OLLAMA_MODEL = "llama3.1:8b"

DEFAULT_INPUT  = "/opt/wazuh-soc/data/alerts_raw.json"
DEFAULT_OUTPUT = "/opt/wazuh-soc/data/triage_report.json"

# How many alerts to send per AI batch
# llama3.1:8b context = 4096 tokens — keep batches small
BATCH_SIZE = 5


# ============================================================
# Ollama API
# ============================================================
def ollama_generate(prompt, system=None, timeout=600):
    """
    Send a prompt to Ollama and return the response text.
    Uses the /api/generate endpoint (non-streaming).
    """
    payload = {
        "model":  OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,   # low temp = consistent, factual output
            "num_predict": 1024,
        }
    }
    if system:
        payload["system"] = system

    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read().decode())
            return result.get("response", "").strip()
    except urllib.error.URLError as e:
        print(f"[-] Cannot reach Ollama at {OLLAMA_URL}: {e.reason}", file=sys.stderr)
        print("[-] Is Ollama running on the Alienware? Check OLLAMA_HOST binding.",
              file=sys.stderr)
        sys.exit(1)


def check_ollama():
    """Verify Ollama is reachable and the model is loaded."""
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/tags")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            models = [m["name"] for m in data.get("models", [])]
            if OLLAMA_MODEL not in models and not any(
                OLLAMA_MODEL.split(":")[0] in m for m in models
            ):
                print(f"[-] Model {OLLAMA_MODEL} not found. Available: {models}",
                      file=sys.stderr)
                sys.exit(1)
            return True
    except urllib.error.URLError as e:
        print(f"[-] Ollama unreachable at {OLLAMA_URL}: {e.reason}", file=sys.stderr)
        sys.exit(1)


# ============================================================
# Prompt builders
# ============================================================
SYSTEM_PROMPT = """You are an expert threat intelligence analyst at a top-tier SOC.
You are analyzing real attack data captured by a Cowrie SSH honeypot deployed on
DigitalOcean NYC1. Your analysis must be SPECIFIC and DETAILED — not generic.

Rules:
- Reference actual IP addresses, countries, and organizations by name
- Quote actual commands and credentials observed
- Identify specific attack tools and techniques by name (e.g. Mirai, mdrfckr botnet)
- Explain WHY each finding matters operationally
- Give specific, actionable recommendations (not generic advice)
- If you see the same credential or command repeated many times, call it out as a botnet
- The SSH key with username 'mdrfckr' is a known botnet implant — identify it by name
- Always structure your output as valid JSON with no markdown fences"""


def build_batch_prompt(alerts):
    """
    Build a detailed prompt for a batch of alerts with full context.
    """
    alert_lines = []
    for i, a in enumerate(alerts, 1):
        parts = [f"Alert {i}: [{a['severity'].upper()}] {a['rule_desc']}"]
        if a["src_ip"]:
            loc = f"{a['src_country']}" if a['src_country'] else "Unknown country"
            org = f", {a['src_org']}" if a['src_org'] else ""
            parts.append(f"  Source IP: {a['src_ip']} ({loc}{org})")
        if a["username"] and a["password"]:
            parts.append(f"  Credential: {a['username']}/{a['password']}")
        elif a["username"]:
            parts.append(f"  Username: {a['username']}")
        if a["command"]:
            cmd = a["command"][:200]
            parts.append(f"  Command: {cmd}")
        if a["eventid"]:
            parts.append(f"  Event type: {a['eventid']}")
        if a["mitre_tactics"]:
            ids = ", ".join(a.get("mitre_ids", []))
            tactics = ", ".join(a["mitre_tactics"])
            parts.append(f"  MITRE: {tactics} ({ids})")
        if a["session"]:
            parts.append(f"  Session: {a['session']}")
        alert_lines.append("\n".join(parts))

    alerts_text = "\n\n".join(alert_lines)

    prompt = f"""Analyze these {len(alerts)} real honeypot alerts. Be SPECIFIC — name actual IPs,
credentials, commands, and organizations. Do NOT give generic advice.

ALERTS:
{alerts_text}

Respond with ONLY valid JSON, no markdown:
{{
  "threat_assessment": "3-4 sentences. Name specific IPs, countries, orgs. Describe the attack pattern precisely.",
  "attacker_profile": "2-3 sentences. Identify if this is a botnet, script kiddie, or targeted attack. Name known tools if recognized.",
  "top_threats": [
    {{
      "alert_number": 1,
      "threat_type": "specific threat name (e.g. SSH Key Implant, Mirai Botnet, Credential Stuffing)",
      "explanation": "2 sentences — what specifically happened and why it matters",
      "recommended_action": "specific action (e.g. block ASN AS12345, add this SSH key to watchlist)"
    }}
  ],
  "iocs": {{
    "ip_addresses": ["IP (Country, Org) — list all notable ones"],
    "credentials": ["user/pass — flag if seen repeatedly"],
    "commands": ["actual command — explain what it does"]
  }},
  "mitre_summary": "2 sentences naming specific techniques and their IDs (e.g. T1110.001 Password Guessing)",
  "severity_verdict": "critical|high|medium|low",
  "analyst_notes": "2-3 sentences of specific observations — patterns, anomalies, threat actor signatures"
}}"""

    return prompt


def build_executive_prompt(stats, triage_results):
    """Build an executive summary prompt from aggregated triage data."""

    # Aggregate IOCs across all batches
    all_ips      = []
    all_creds    = []
    all_verdicts = Counter()

    for r in triage_results:
        iocs = r.get("iocs", {})
        all_ips.extend(iocs.get("ip_addresses", []))
        all_creds.extend(iocs.get("credentials", []))
        verdict = r.get("severity_verdict", "")
        if verdict:
            all_verdicts[verdict] += 1

    top_verdict = all_verdicts.most_common(1)[0][0] if all_verdicts else "medium"

    # Build top credentials and commands summary for context
    top_creds = dict(list(stats.get('top_credentials', {}).items())[:5]) if isinstance(stats.get('top_credentials'), dict) else {}
    top_cmds  = list(stats.get('top_commands', {}).keys())[:3] if isinstance(stats.get('top_commands'), dict) else []
    top_countries = dict(list(stats.get('top_countries', {}).items())[:8])
    top_orgs      = dict(list(stats.get('top_orgs', {}).items())[:5])

    prompt = f"""Write a detailed executive summary of a honeypot security operation for a CISO.
Be SPECIFIC — include actual country names, IP addresses, credential patterns, and commands.
Respond with ONLY a JSON object, no markdown.

OPERATIONAL DATA:
- Total alerts: {stats['total']} | Severity: {json.dumps(stats['by_severity'])}
- Top attacker countries: {json.dumps(top_countries)}
- Top hosting orgs: {json.dumps(top_orgs)}
- Top attacker IPs: {list(set(all_ips))[:8]}
- MITRE tactics: {json.dumps(list(stats.get('mitre_tactics', {}).keys()))}
- Most used credentials: {json.dumps(top_creds)}
- Most executed commands: {top_cmds}
- All triage verdicts: {json.dumps(dict(all_verdicts))}
- Overall verdict: {top_verdict}

Respond with ONLY this JSON:
{{
  "executive_summary": "4-5 sentences for a CISO. Name specific countries, mention the dominant botnet credential (345gs5662d34), note the SSH key implant attempts, quantify the threat.",
  "key_findings": [
    "Specific finding with numbers and country/IP names",
    "Specific finding about credential patterns observed",
    "Specific finding about commands/techniques used",
    "Specific finding about attack infrastructure",
    "Specific finding about threat actor profile"
  ],
  "threat_level": "critical|high|medium|low",
  "recommended_actions": [
    "Specific action with details",
    "Specific action with details",
    "Specific action with details",
    "Specific action with details"
  ],
  "threat_actors": "2-3 sentences identifying the likely threat actors by behavior pattern, tools used, and infrastructure",
  "time_period": "alerts analyzed",
  "generated_at": "{datetime.now(timezone.utc).isoformat()}"
}}"""

    return prompt


# ============================================================
# Triage modes
# ============================================================
def triage_batch_mode(alerts, stats):
    """
    Analyze alerts in batches of BATCH_SIZE.
    Returns list of triage result dicts.
    """
    results = []
    total_batches = (len(alerts) + BATCH_SIZE - 1) // BATCH_SIZE

    for i in range(0, len(alerts), BATCH_SIZE):
        batch     = alerts[i:i + BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1

        print(f"[+] Analyzing batch {batch_num}/{total_batches} "
              f"({len(batch)} alerts)...", end=" ", flush=True)

        prompt   = build_batch_prompt(batch)
        response = ollama_generate(prompt, system=SYSTEM_PROMPT)

        # Parse JSON response
        try:
            # Strip any markdown fences if the model adds them
            clean = response.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            result = json.loads(clean.strip())
            result["batch_number"]  = batch_num
            result["alerts_in_batch"] = len(batch)
            results.append(result)
            verdict = result.get("severity_verdict", "?")
            print(f"verdict={verdict}")
        except json.JSONDecodeError:
            print("(JSON parse failed — saving raw response)")
            results.append({
                "batch_number":    batch_num,
                "alerts_in_batch": len(batch),
                "raw_response":    response,
                "parse_error":     True,
            })

    return results


def triage_summary_mode(alerts, stats):
    """
    Summary mode: build full intelligence summary from OpenSearch,
    send to LLM in one comprehensive prompt for maximum depth.
    """
    minutes = stats.get("window_minutes", 10080) if isinstance(stats, dict) else 10080

    print(f"[+] Building intelligence summary from OpenSearch (window: {minutes} min)...")
    intel = build_intelligence_summary(minutes)

    print(f"[+] Summary mode: {intel['total_events']:,} total events, "
          f"{intel['high_severity']:,} high, "
          f"{len(intel['notable_events'])} notable events for analysis...")

    prompt = f"""You are analyzing a Cowrie SSH honeypot deployment. You have access to
COMPLETE AGGREGATED INTELLIGENCE across ALL {intel['total_events']:,} events — not just a sample.
Be SPECIFIC, DETAILED, and name actual IPs, countries, organizations, credentials, and commands.

=== FULL INTELLIGENCE SUMMARY ===
Window: last {intel['window_minutes']} minutes
Total events: {intel['total_events']:,}
High severity: {intel['high_severity']:,} | Medium: {intel['medium_severity']:,}
Login successes: {intel['login_success']:,} | Login failures: {intel['login_failed']:,}
Commands executed: {intel['commands_executed']:,} | Files downloaded: {intel['files_downloaded']:,}

TOP 20 ATTACKER IPs (by volume):
{chr(10).join(f"  {ip}" for ip in intel['top_attacker_ips'])}

TOP CREDENTIALS USED:
{chr(10).join(f"  {c}" for c in intel['top_credentials'][:15])}

TOP COMMANDS EXECUTED:
{chr(10).join(f"  {c}" for c in intel['top_commands'][:10])}

MITRE ATT&CK TACTICS:
{json.dumps(intel['mitre_tactics'], indent=2)}

MITRE TECHNIQUE IDs: {', '.join(intel['mitre_technique_ids'])}

=== 20 MOST NOTABLE INDIVIDUAL EVENTS ===
{json.dumps(intel['notable_events'], indent=2)}

Respond with ONLY valid JSON:
{{
  "threat_assessment": "4-5 sentences. Use specific numbers, name top attacker IPs with countries/orgs, describe the dominant attack pattern. Mention the botnet if credentials repeat.",
  "attacker_profile": "3-4 sentences. Identify specific threat actors by behavior. Is this Mirai? A credential stuffing botnet? Name the mdrfckr SSH key implant if present. Characterize sophistication level.",
  "top_threats": [
    {{
      "threat_type": "specific name",
      "count": "how many times observed",
      "explanation": "2-3 sentences with specific details — IPs, creds, commands involved",
      "recommended_action": "specific action with details (e.g. block AS12345, add IOC to threat intel)"
    }}
  ],
  "iocs": {{
    "ip_addresses": ["IP (Country, Org) for top 10 most active"],
    "credentials": ["top credentials with repeat counts"],
    "commands": ["notable commands with what they do"]
  }},
  "mitre_summary": "3 sentences naming specific techniques by ID and name, explaining what they indicate",
  "severity_verdict": "critical|high|medium|low",
  "analyst_notes": "3-4 sentences of specific threat intelligence observations — patterns, anomalies, attack infrastructure, threat actor signatures"
}}"""

    response = ollama_generate(prompt, system=SYSTEM_PROMPT, timeout=300)
    try:
        clean = response.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        result = json.loads(clean.strip())
        result["batch_number"] = 1
        result["alerts_in_batch"] = intel["total_events"]
        return [result]
    except json.JSONDecodeError:
        return [{"raw_response": response, "parse_error": True}]


def triage_executive_mode(alerts, stats, batch_results):
    """
    Executive mode: use full intelligence summary for CISO-level output.
    Runs after batch analysis to add strategic context.
    """
    print("[+] Generating executive summary with full intelligence context...")

    minutes = stats.get("window_minutes", 10080) if isinstance(stats, dict) else 10080
    intel   = build_intelligence_summary(minutes)

    # Extract verdicts from batch results
    from collections import Counter
    verdicts = Counter(r.get("severity_verdict","") for r in batch_results if "severity_verdict" in r)
    top_verdict = verdicts.most_common(1)[0][0] if verdicts else "high"

    prompt = f"""Write a comprehensive executive security briefing for a CISO based on
real honeypot threat intelligence data. Be SPECIFIC — include actual numbers,
country names, IP addresses, and attack patterns.

=== COMPLETE THREAT INTELLIGENCE ===
Window: last {intel['window_minutes']} minutes
Total events: {intel['total_events']:,}
High severity: {intel['high_severity']:,} | Medium: {intel['medium_severity']:,}
Successful logins: {intel['login_success']:,} | Failed attempts: {intel['login_failed']:,}
Commands run by attackers: {intel['commands_executed']:,}
Files downloaded by attackers: {intel['files_downloaded']:,}

TOP ATTACKER INFRASTRUCTURE:
{chr(10).join(f"  {ip}" for ip in intel['top_attacker_ips'][:12])}

CREDENTIAL INTELLIGENCE:
{chr(10).join(f"  {c}" for c in intel['top_credentials'][:10])}

COMMAND INTELLIGENCE:
{chr(10).join(f"  {c}" for c in intel['top_commands'][:8])}

MITRE ATT&CK: {json.dumps(intel['mitre_tactics'])}
TECHNIQUE IDs: {', '.join(intel['mitre_technique_ids'])}
OVERALL VERDICT: {top_verdict.upper()}

Respond with ONLY valid JSON:
{{
  "executive_summary": "5-6 sentences for a CISO. Start with the threat level and total scope. Name the dominant attack source countries. Describe the primary attack methodology. Mention credential patterns (the 345gs5662d34 botnet if present). Quantify the successful intrusion attempts. End with operational impact assessment.",
  "key_findings": [
    "Finding 1: specific numbers and geography (e.g. X attacks from Y countries, top attacker Z org)",
    "Finding 2: credential analysis (dominant patterns, botnet signatures)",
    "Finding 3: command/technique analysis (what attackers did after login)",
    "Finding 4: attack infrastructure (hosting providers, ASNs used)",
    "Finding 5: MITRE ATT&CK coverage and technique breakdown"
  ],
  "threat_level": "{top_verdict}",
  "recommended_actions": [
    "Specific action 1 with details",
    "Specific action 2 with details",
    "Specific action 3 with details",
    "Specific action 4 with details",
    "Specific action 5 with details"
  ],
  "threat_actors": "3-4 sentences. Characterize the threat actors by their tools, credentials, infrastructure, and behavior. Identify botnets by name if recognizable. Assess nation-state vs criminal vs opportunistic.",
  "ioc_summary": {{
    "top_ips": [list top 5 attacker IPs with country and org],
    "botnet_credentials": [list the most-repeated credential pairs],
    "malicious_commands": [list the most executed post-login commands]
  }},
  "time_period": "last {intel['window_minutes']} minutes",
  "generated_at": "{datetime.now(timezone.utc).isoformat()}"
}}"""

    response = ollama_generate(prompt, system=SYSTEM_PROMPT, timeout=300)
    try:
        clean = response.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        return json.loads(clean.strip())
    except json.JSONDecodeError:
        return {"raw_response": response, "parse_error": True}


# ============================================================
# CLI
# ============================================================
def parse_args():
    parser = argparse.ArgumentParser(
        description="AI-powered triage of Wazuh honeypot alerts via Ollama",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  summary    Analyze top 10 highest-severity alerts (fast, ~30s)
  full       Analyze all alerts in batches of 10 (thorough, slower)
  executive  Run full analysis + generate CISO-level executive summary

Examples:
  python3 ai_triage.py --mode summary
  python3 ai_triage.py --mode full --input /opt/wazuh-soc/data/alerts_raw.json
  python3 ai_triage.py --mode executive
        """
    )
    parser.add_argument("--input",  type=str, default=DEFAULT_INPUT,
                        help=f"Alert poller output JSON (default: {DEFAULT_INPUT})")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT,
                        help=f"Triage report output (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--mode",   type=str, default="summary",
                        choices=["summary", "full", "executive"],
                        help="Triage mode (default: summary)")
    parser.add_argument("--minutes", type=int, default=10080,
                        help="Time window in minutes for intelligence query (default: 10080 = 7 days)")
    parser.add_argument("--no-save", action="store_true",
                        help="Print report to stdout only")
    return parser.parse_args()


# ============================================================
# Main
# ============================================================
def main():
    args = parse_args()

    print("[+] ai_triage.py — AI Alert Triage")
    print(f"[+] Model:  {OLLAMA_MODEL} @ {OLLAMA_URL}")
    print(f"[+] Mode:   {args.mode}")
    print(f"[+] Input:  {args.input}")
    print()

    # Verify Ollama is reachable
    print("[+] Checking Ollama connection...")
    check_ollama()
    print(f"[+] {OLLAMA_MODEL} is ready (RTX 4070)")
    print()

    # Load alerts
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[-] Input file not found: {args.input}", file=sys.stderr)
        print("[-] Run alert_poller.py first to generate alerts", file=sys.stderr)
        sys.exit(1)

    with open(input_path) as f:
        poller_output = json.load(f)

    alerts = poller_output.get("alerts", [])
    stats  = poller_output.get("stats", {})
    polled_at = poller_output.get("polled_at", "")

    print(f"[+] Loaded {len(alerts)} alerts (polled at {polled_at})")
    print(f"[+] Severity breakdown: {stats.get('by_severity', {})}")
    print(f"[+] Honeypot alerts: {stats.get('honeypot_alerts', 0)}")
    print()

    if not alerts:
        print("[-] No alerts to analyze")
        sys.exit(0)

    # Run triage
    batch_results    = []
    executive_summary = None

    # Pass minutes for intelligence window
    if not hasattr(stats, "get"):
        stats = {}
    stats["window_minutes"] = args.minutes

    # Pass minutes for intelligence window
    if not hasattr(stats, "get"):
        stats = {}
    stats["window_minutes"] = args.minutes

    if args.mode == "summary":
        batch_results = triage_summary_mode(alerts, stats)

    elif args.mode == "full":
        batch_results = triage_batch_mode(alerts, stats)

    elif args.mode == "executive":
        batch_results    = triage_batch_mode(alerts, stats)
        executive_summary = triage_executive_mode(alerts, stats, batch_results)

    # Build final report
    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "mode":            args.mode,
        "model":           OLLAMA_MODEL,
        "ollama_host":     OLLAMA_URL,
        "alerts_analyzed": len(alerts),
        "stats":           stats,
        "triage_results":  batch_results,
    }
    if executive_summary:
        report["executive_summary"] = executive_summary

    # Print highlights
    print()
    print("[+] Triage complete")
    for r in batch_results:
        if "parse_error" not in r:
            print(f"\n    Batch {r.get('batch_number', 1)} verdict: "
                  f"{r.get('severity_verdict', '?').upper()}")
            assessment = r.get("threat_assessment", "")
            if assessment:
                # Wrap at 70 chars for readability
                words = assessment.split()
                line = "    "
                for word in words:
                    if len(line) + len(word) > 74:
                        print(line)
                        line = "    " + word + " "
                    else:
                        line += word + " "
                if line.strip():
                    print(line)

    if executive_summary and "executive_summary" in executive_summary:
        print(f"\n[+] Executive summary:")
        summary = executive_summary["executive_summary"]
        words = summary.split()
        line = "    "
        for word in words:
            if len(line) + len(word) > 74:
                print(line)
                line = "    " + word + " "
            else:
                line += word + " "
        if line.strip():
            print(line)

    # Save or print
    if args.no_save:
        print("\n[+] Full report (stdout):")
        print(json.dumps(report, indent=2))
    else:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)
        size = out_path.stat().st_size
        print(f"\n[+] Report saved → {out_path} ({size:,} bytes)")

    print("[+] Done.")


if __name__ == "__main__":
    main()
