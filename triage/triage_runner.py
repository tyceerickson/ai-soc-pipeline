#!/usr/bin/env python3
"""
triage_runner.py — SOC Pipeline Orchestrator
============================================
Chains the full AI-powered SOC pipeline in sequence:
  1. export_to_wazuh.py  — refresh normalized honeypot log
  2. alert_poller.py     — pull recent alerts from OpenSearch
  3. ai_triage.py        — AI analysis via Ollama (Alienware RTX 4070)

Designed to run every 30 minutes via cron.
All output is logged to /opt/wazuh-soc/logs/runner.log

Part of the wazuh-soc-pipeline — Project 4
Runs on: Ubuntu Server (192.168.10.4)

Usage:
    python3 triage_runner.py
    python3 triage_runner.py --mode summary
    python3 triage_runner.py --mode executive
    python3 triage_runner.py --dry-run
"""

import argparse
import subprocess
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

# ============================================================
# Configuration
# ============================================================
PYTHON          = "/usr/bin/python3"

EXPORT_SCRIPT   = "/opt/cowrie-tools/pipeline/export_to_wazuh.py"
POLLER_SCRIPT   = "/opt/wazuh-soc/triage/alert_poller.py"
TRIAGE_SCRIPT   = "/opt/wazuh-soc/triage/ai_triage.py"

ENRICHED_INPUT  = "/opt/cowrie-logs/cowrie_enriched.json"
WAZUH_OUTPUT    = "/opt/cowrie-logs/wazuh/"
ALERTS_OUTPUT   = "/opt/wazuh-soc/data/alerts_raw.json"
TRIAGE_OUTPUT   = "/opt/wazuh-soc/data/triage_report.json"
LOG_FILE        = "/opt/wazuh-soc/logs/runner.log"

# Alert poller settings
POLL_MINUTES    = 60       # look-back window
POLL_MIN_LEVEL  = 6        # minimum rule level
POLL_LIMIT      = 100      # max alerts per run


# ============================================================
# Logging
# ============================================================
def log(msg, level="INFO"):
    """Write timestamped log entry to both stdout and log file."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"[{ts}] [{level}] {msg}"
    print(line)
    try:
        Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def log_separator():
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"\n{'='*60}\n[{ts}] Pipeline run starting\n{'='*60}"
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ============================================================
# Step runner
# ============================================================
def run_step(step_name, cmd, dry_run=False):
    """
    Run a pipeline step as a subprocess.
    Returns True on success, False on failure.
    Streams output live to the log.
    """
    log(f"Starting: {step_name}")
    log(f"Command:  {' '.join(cmd)}")

    if dry_run:
        log(f"DRY RUN — skipping execution")
        return True

    try:
        result = subprocess.run(
            cmd,
            capture_output=False,   # let output stream to terminal
            text=True,
            timeout=300,            # 5 minute timeout per step
        )

        if result.returncode == 0:
            log(f"Completed: {step_name} (exit 0)")
            return True
        else:
            log(f"FAILED: {step_name} (exit {result.returncode})", level="ERROR")
            return False

    except subprocess.TimeoutExpired:
        log(f"TIMEOUT: {step_name} exceeded 5 minutes", level="ERROR")
        return False
    except FileNotFoundError as e:
        log(f"NOT FOUND: {e}", level="ERROR")
        return False
    except Exception as e:
        log(f"ERROR in {step_name}: {e}", level="ERROR")
        return False


# ============================================================
# Pipeline steps
# ============================================================
def step_export(dry_run=False):
    """Step 1 — Refresh wazuh-cowrie.json from enriched data."""
    cmd = [
        PYTHON, EXPORT_SCRIPT,
        "--input",       ENRICHED_INPUT,
        "--output-dir",  WAZUH_OUTPUT,
        "--wazuh-manager", "127.0.0.1",
    ]
    return run_step("export_to_wazuh", cmd, dry_run)


def step_poll(dry_run=False):
    """Step 2 — Pull recent alerts from OpenSearch."""
    cmd = [
        PYTHON, POLLER_SCRIPT,
        "--minutes",       str(POLL_MINUTES),
        "--min-level",     str(POLL_MIN_LEVEL),
        "--limit",         str(POLL_LIMIT),
        "--honeypot-only",
        "--output",        ALERTS_OUTPUT,
    ]
    return run_step("alert_poller", cmd, dry_run)


def step_triage(mode="summary", dry_run=False):
    """Step 3 — AI triage analysis via Ollama."""
    cmd = [
        PYTHON, TRIAGE_SCRIPT,
        "--mode",    mode,
        "--input",   ALERTS_OUTPUT,
        "--output",  TRIAGE_OUTPUT,
    ]
    return run_step(f"ai_triage ({mode})", cmd, dry_run)


# ============================================================
# CLI
# ============================================================
def parse_args():
    parser = argparse.ArgumentParser(
        description="SOC pipeline orchestrator — chains export → poll → triage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  summary    Analyze top 10 highest-severity alerts (fast, ~45s)
  executive  Full batch analysis + CISO summary (thorough, ~5 min)

Examples:
  python3 triage_runner.py
  python3 triage_runner.py --mode executive
  python3 triage_runner.py --dry-run
  python3 triage_runner.py --skip-export
        """
    )
    parser.add_argument("--mode",        type=str, default="summary",
                        choices=["summary", "executive"],
                        help="Triage mode (default: summary)")
    parser.add_argument("--dry-run",     action="store_true",
                        help="Print commands without executing")
    parser.add_argument("--skip-export", action="store_true",
                        help="Skip export_to_wazuh.py step (use existing file)")
    return parser.parse_args()


# ============================================================
# Main
# ============================================================
def main():
    args = parse_args()

    log_separator()
    log(f"triage_runner.py — SOC Pipeline Orchestrator")
    log(f"Mode: {args.mode} | Dry run: {args.dry_run}")

    start = datetime.now(timezone.utc)
    results = {}

    # Step 1 — Export (optional skip for fast runs)
    if args.skip_export:
        log("Skipping export step (--skip-export)")
        results["export"] = True
    else:
        results["export"] = step_export(args.dry_run)
        if not results["export"]:
            log("Export step failed — continuing with existing wazuh-cowrie.json",
                level="WARN")

    # Step 2 — Poll
    results["poll"] = step_poll(args.dry_run)
    if not results["poll"]:
        log("Poll step failed — aborting pipeline", level="ERROR")
        sys.exit(1)

    # Step 3 — Triage
    results["triage"] = step_triage(args.mode, args.dry_run)
    if not results["triage"]:
        log("Triage step failed", level="ERROR")
        sys.exit(1)

    # Summary
    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    log(f"Pipeline complete in {elapsed:.0f}s")
    log(f"Results: export={results['export']} | "
        f"poll={results['poll']} | triage={results['triage']}")
    log(f"Output: {TRIAGE_OUTPUT}")


if __name__ == "__main__":
    main()
