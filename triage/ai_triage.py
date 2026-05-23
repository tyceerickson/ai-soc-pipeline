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
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

# ============================================================
# Configuration
# ============================================================
OLLAMA_URL   = "http://100.72.171.104:11434"
OLLAMA_MODEL = "llama3.1:8b"

DEFAULT_INPUT  = "/opt/wazuh-soc/data/alerts_raw.json"
DEFAULT_OUTPUT = "/opt/wazuh-soc/data/triage_report.json"

# How many alerts to send per AI batch
# llama3.1:8b context = 4096 tokens — keep batches small
BATCH_SIZE = 10


# ============================================================
# Ollama API
# ============================================================
def ollama_generate(prompt, system=None, timeout=120):
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
SYSTEM_PROMPT = """You are a senior SOC analyst reviewing honeypot security alerts.
Your job is to analyze attack data captured by a Cowrie SSH honeypot and provide
clear, actionable intelligence. Be concise and precise. Use security terminology
correctly. Always structure your output as valid JSON."""


def build_batch_prompt(alerts):
    """
    Build a prompt for a batch of alerts.
    Sends compact alert data to stay within context limits.
    """
    # Compact representation for the LLM
    alert_lines = []
    for i, a in enumerate(alerts, 1):
        parts = [f"Alert {i}: [{a['severity'].upper()}] {a['rule_desc']}"]
        if a["src_ip"]:
            loc = a["src_country"] or "Unknown"
            parts.append(f"  Source: {a['src_ip']} ({loc})")
            if a["src_org"]:
                parts.append(f"  Org: {a['src_org']}")
        if a["username"] or a["password"]:
            parts.append(f"  Credentials tried: {a['username']}/{a['password']}")
        if a["command"]:
            parts.append(f"  Command: {a['command']}")
        if a["mitre_tactics"]:
            parts.append(f"  MITRE: {', '.join(a['mitre_tactics'])}")
        if a["eventid"]:
            parts.append(f"  Event: {a['eventid']}")
        alert_lines.append("\n".join(parts))

    alerts_text = "\n\n".join(alert_lines)

    prompt = f"""Analyze these {len(alerts)} honeypot security alerts and respond with ONLY a JSON object.

ALERTS:
{alerts_text}

Respond with ONLY this JSON structure, no other text:
{{
  "threat_assessment": "2-3 sentence overall assessment of this alert batch",
  "attacker_profile": "1-2 sentences describing the likely attacker type and intent",
  "top_threats": [
    {{
      "alert_number": 1,
      "threat_type": "short threat category name",
      "explanation": "1 sentence plain-English explanation",
      "recommended_action": "specific defensive action"
    }}
  ],
  "iocs": {{
    "ip_addresses": ["list of notable attacker IPs"],
    "credentials": ["notable username/password pairs tried"],
    "commands": ["notable commands executed"]
  }},
  "mitre_summary": "1 sentence summarizing observed ATT&CK techniques",
  "severity_verdict": "critical|high|medium|low",
  "analyst_notes": "any additional observations worth flagging"
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

    prompt = f"""Write an executive summary of a honeypot security operation.
Respond with ONLY a JSON object, no other text.

OPERATIONAL DATA:
- Total alerts analyzed: {stats['total']}
- Honeypot alerts: {stats['honeypot_alerts']}
- Severity breakdown: {json.dumps(stats['by_severity'])}
- Top attacker countries: {json.dumps(dict(list(stats.get('top_countries', {}).items())[:5]))}
- MITRE ATT&CK tactics observed: {json.dumps(list(stats.get('mitre_tactics', {}).keys())[:6])}
- Top attacker IPs seen: {list(set(all_ips))[:5]}
- Overall severity verdict: {top_verdict}

Respond with ONLY this JSON structure:
{{
  "executive_summary": "3-4 sentence non-technical summary suitable for a CISO",
  "key_findings": [
    "finding 1",
    "finding 2",
    "finding 3"
  ],
  "threat_level": "critical|high|medium|low",
  "recommended_actions": [
    "action 1",
    "action 2",
    "action 3"
  ],
  "threat_actors": "1-2 sentences characterizing the observed threat actors",
  "time_period": "alerts from the last hour",
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
    """Analyze a representative sample for a quick summary."""
    # Take top alerts by severity level
    sorted_alerts = sorted(alerts, key=lambda a: a["rule_level"], reverse=True)
    sample = sorted_alerts[:BATCH_SIZE]

    print(f"[+] Summary mode: analyzing top {len(sample)} highest-severity alerts...")
    prompt   = build_batch_prompt(sample)
    response = ollama_generate(prompt, system=SYSTEM_PROMPT, timeout=180)

    try:
        clean = response.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        return [json.loads(clean.strip())]
    except json.JSONDecodeError:
        return [{"raw_response": response, "parse_error": True}]


def triage_executive_mode(alerts, stats, batch_results):
    """Generate executive summary from batch results."""
    print("[+] Generating executive summary...")
    prompt   = build_executive_prompt(stats, batch_results)
    response = ollama_generate(prompt, system=SYSTEM_PROMPT, timeout=180)

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
