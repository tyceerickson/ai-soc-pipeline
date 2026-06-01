#!/usr/bin/env python3
"""
parse_nginx.py — nginx access log parser for Wazuh ingestion
Project 4: AI-Powered SOC Pipeline · CMU MSISPM Portfolio · Tyce Erickson

Reads /opt/cowrie-logs/nginx/access.log (standard Combined Log Format),
enriches with GeoIP and scanner identification, writes
/opt/cowrie-logs/wazuh/wazuh-nginx.json for Wazuh agent pickup.

Log format (Combined Log Format):
  IP - - [timestamp] "METHOD path HTTP/ver" status bytes "-" "user-agent" "-"

Run:
  python3 /opt/cowrie-tools/pipeline/parse_nginx.py

Author: Tyce Erickson
"""

import re
import json
import os
import glob
import gzip
import time
import fcntl
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────────────
LOG_INPUT_DIR = "/opt/cowrie-logs/nginx"
LOG_GLOB      = "access.log*"
OUTPUT_FILE   = "/opt/cowrie-logs/wazuh/wazuh-nginx.json"
STATE_FILE    = "/opt/cowrie-logs/nginx/.parse_state.json"
GEOIP_CACHE   = "/opt/cowrie-logs/geoip_cache.json"
GEOIP_CITY_DB = "/opt/geoip/GeoLite2-City.mmdb"
GEOIP_ASN_DB  = "/opt/geoip/GeoLite2-ASN.mmdb"
SENSOR        = "digitalocean-nyc1"
MAX_LINES     = 200_000
LOOKBACK_HOURS = 25

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("parse-nginx")

# ── Combined Log Format regex ────────────────────────────────────────────────
RE_CLF = re.compile(
    r'^(\S+)\s+'           # 1: src_ip
    r'\S+\s+\S+\s+'        # ident, auth (always "-")
    r'\[([^\]]+)\]\s+'     # 2: timestamp  [28/May/2026:01:52:36 +0000]
    r'"([A-Z\x00-\xff]+)\s+'  # 3: method
    r'(\S*)\s+'            # 4: path
    r'([^"]+)"\s+'         # 5: protocol
    r'(\d{3})\s+'          # 6: status
    r'(\d+|-)\s+'          # 7: bytes
    r'"([^"]*)"\s+'        # 8: referer
    r'"([^"]*)"'           # 9: user-agent
)

TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# ── Scanner / threat intelligence fingerprints ───────────────────────────────
SCANNER_PATTERNS = [
    # Internet census / research
    (r'masscan|shodan|censys|zgrab|nmap|zmap',             "Internet Scanner"),
    (r'ivre',                                               "IVRE Scanner"),
    (r'internet-measurement|internetmeasurement',           "Research Scanner"),
    (r'python-requests',                                    "Python Scanner"),
    (r'go-http-client',                                     "Go Scanner"),
    (r'curl/',                                              "curl Client"),
    (r'wget/',                                              "wget Client"),
    # Botnets / IoT malware
    (r'mirai|\bmozi\b|gafgyt|satori|bashlite|hajime|tsunami|kaiten|dofloo',                 "IoT Botnet"),
    (r'libwww-perl|lwp-trivial',                            "Perl Bot"),
    # Vulnerability scanners
    (r'nikto|nessus|openvas|acunetix|burpsuite|nuclei',    "Vuln Scanner"),
    (r'sqlmap',                                             "SQLMap"),
    (r'wfuzz|gobuster|dirbuster|dirb|feroxbuster',         "Dir Brute-Force"),
    (r'hydra|medusa|patator',                               "Cred Brute-Force"),
    # CVE-specific probes
    (r'log4j|\$\{jndi',                                     "Log4Shell Probe"),
    (r'wp-login|wordpress|xmlrpc',                          "WordPress Probe"),
    (r'phpmyadmin|pma',                                     "phpMyAdmin Probe"),
    (r'\.git/',                                             "Git Exposure Probe"),
    (r'\.env',                                              "Env File Probe"),
    (r'manager/html|tomcat',                                "Tomcat Probe"),
    (r'cgi-bin',                                            "CGI Probe"),
    (r'luci|stok=',                                         "Router Firmware Probe"),
    (r'/SDK/webLanguage',                                   "Hikvision CVE Probe"),
    # Generic
    (r'<script>|<img|onmouseover',                          "XSS Probe"),
    (r'union.*select|exec\s+xp_|0x3c62723e',               "SQLi Probe"),
    (r'cmd=|exec=|system\(',                                "RCE Probe"),
]

SCANNER_RE = [(re.compile(p, re.IGNORECASE), label) for p, label in SCANNER_PATTERNS]

# Fall-through markers — consulted ONLY after the real signatures above miss.
LIBRARY_UA_RE = re.compile(
    r'java/|okhttp|apache-httpclient|httpclient|node-fetch|axios|libwww|lwp::|'
    r'python-urllib|python/|urllib|aiohttp|httpx|guzzle|winhttp|wininet|'
    r'mechanize|scrapy|colly|restsharp|postmanruntime|insomnia|'
    r'headlesschrome|phantomjs|selenium|puppeteer|playwright',
    re.IGNORECASE,
)
BROWSER_UA_RE = re.compile(
    r'mozilla/|applewebkit|gecko/|chrome/|safari/|firefox/|edge/|opera/|msie ',
    re.IGNORECASE,
)

# ── Path classification ───────────────────────────────────────────────────────
PATH_CATEGORIES = [
    (r'\.env$|\.env\..*$',                     "env-file"),
    (r'\.git/',                                 "git-exposure"),
    (r'wp-login|wp-content|wordpress|xmlrpc',  "wordpress"),
    (r'phpmyadmin|pma/',                        "phpmyadmin"),
    (r'manager/html',                           "tomcat-manager"),
    (r'cgi-bin',                                "cgi"),
    (r'luci|stok=',                             "router-admin"),
    (r'/SDK/webLanguage',                       "hikvision-rce"),
    (r'jndi:|log4j',                            "log4shell"),
    (r'admin|administrator',                    "admin-panel"),
    (r'shell|cmd\.php|webshell',                "webshell"),
    (r'setup\.php|install\.php',                "setup-probe"),
    (r'/api/',                                  "api-probe"),
    (r'^/$',                                    "root"),
    (r'favicon\.ico',                           "favicon"),
]
PATH_RE = [(re.compile(p, re.IGNORECASE), cat) for p, cat in PATH_CATEGORIES]


def classify_path(path: str) -> str:
    for pattern, cat in PATH_RE:
        if pattern.search(path):
            return cat
    return "other"


def identify_scanner(ua: str, path: str, status: int = 0, method: str = "GET") -> str:
    ua = ua or ""
    path = path or ""
    combined = ua + " " + path
    # 1) Real signatures win first (tool names, botnets, CVE paths)
    for pattern, label in SCANNER_RE:
        if pattern.search(combined):
            return label
    # 2) Fall-through so nothing is left "Unknown".
    ua_stripped = ua.strip()
    if ua_stripped in ("", "-"):
        return "No User-Agent"
    if LIBRARY_UA_RE.search(ua):
        return "HTTP Library"
    if BROWSER_UA_RE.search(ua):
        if status in (400, 403, 404, 405, 500) or method not in ("GET", "HEAD"):
            return "Spoofed Browser"
        return "Browser-Like Crawler"
    return "Other Automated"


def wazuh_event_id(method: str, status: int, path: str, scanner: str) -> str:
    if any(x in path for x in ["jndi:", "log4j"]):
        return "nginx.probe.log4shell"
    if ".env" in path:
        return "nginx.probe.env_file"
    if ".git" in path:
        return "nginx.probe.git"
    if "wp-login" in path or "xmlrpc" in path:
        return "nginx.probe.wordpress"
    if "manager/html" in path:
        return "nginx.probe.tomcat"
    if "luci" in path or "stok=" in path:
        return "nginx.probe.router"
    if "/SDK/" in path:
        return "nginx.probe.hikvision"
    if status == 200 and method == "GET":
        return "nginx.request.success"
    if status in (400, 405):
        return "nginx.request.bad"
    if status == 404:
        return "nginx.probe.404"
    return "nginx.request.other"


def wazuh_level_for(method: str, status: int, path: str, scanner: str) -> int:
    if any(x in path for x in ["jndi:", "log4j", ".env", ".git"]):
        return 8
    if "Vuln Scanner" in scanner or "Dir Brute" in scanner:
        return 6
    if status == 200 and method in ("POST", "PUT"):
        return 7
    if status == 200:
        return 3
    return 3


# ── GeoIP (same pattern as parse_dionaea.py) ─────────────────────────────────
_geoip_cache: dict = {}
_geoip_cache_ts: float = 0


def load_geoip_cache() -> dict:
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


def resolve_ip(ip: str) -> dict:
    cache = load_geoip_cache()
    if ip in cache and cache[ip].get("country"):
        c = cache[ip]
        return {
            "country_name": c.get("country", ""),
            "country_code": "",
            "city_name":    c.get("city", ""),
            "org":          c.get("org", ""),
            "asn":          "",
        }
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


# ── State ─────────────────────────────────────────────────────────────────────
def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"last_ts": 0}


def save_state(state: dict):
    try:
        Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as e:
        log.warning("Could not save state: %s", e)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    cutoff = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)

    log_files = sorted(glob.glob(os.path.join(LOG_INPUT_DIR, LOG_GLOB)))
    if not log_files:
        log.warning("No nginx log files found in %s", LOG_INPUT_DIR)
        return

    events = []
    lines_parsed = 0
    lines_skipped = 0

    for log_path in log_files:
        try:
            if log_path.endswith(".gz"):
                opener = lambda p: gzip.open(p, "rt", encoding="utf-8", errors="replace")
            else:
                opener = lambda p: open(p, encoding="utf-8", errors="replace")

            with opener(log_path) as f:
                for raw_line in f:
                    if lines_parsed >= MAX_LINES:
                        break
                    lines_parsed += 1
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue

                    m = RE_CLF.match(raw_line)
                    if not m:
                        lines_skipped += 1
                        continue

                    (src_ip, ts_str, method, path, protocol,
                     status_s, bytes_s, referer, user_agent) = m.groups()

                    # Parse timestamp
                    try:
                        ts = datetime.strptime(ts_str, TS_FORMAT)
                        if ts.timestamp() < cutoff.timestamp():
                            lines_skipped += 1
                            continue
                        ts_iso = ts.astimezone(timezone.utc).isoformat()
                    except Exception:
                        ts_iso = datetime.now(timezone.utc).isoformat()

                    status  = int(status_s)
                    byte_ct = int(bytes_s) if bytes_s != "-" else 0
                    scanner = identify_scanner(user_agent, path, status, method)
                    path_cat = classify_path(path)
                    eventid  = wazuh_event_id(method, status, path, scanner)
                    level    = wazuh_level_for(method, status, path, scanner)

                    geo = resolve_ip(src_ip)

                    event = {
                        "timestamp":      ts_iso,
                        "eventid":        eventid,
                        "honeypot":       "nginx",
                        "honeypot_type":  "web_honeypot",
                        "honeypot_sensor": SENSOR,
                        "src_ip":         src_ip,
                        "http_method":    method,
                        "http_path":      path[:500],
                        "http_status":    status,
                        "http_bytes":     byte_ct,
                        "http_protocol":  protocol.strip(),
                        "user_agent":     user_agent[:500],
                        "referer":        referer if referer != "-" else "",
                        "scanner_type":   scanner,
                        "path_category":  path_cat,
                        "location":       geo,
                        "wazuh_rule_hint": 100300,
                        "wazuh_level":    level,
                    }
                    events.append(event)

        except Exception as e:
            log.error("Error reading %s: %s", log_path, e)
            continue

    # Deduplicate: same IP + path + 1-min window = one event
    seen = set()
    deduped = []
    for ev in events:
        ts_min = ev["timestamp"][:15]
        key = (ev["src_ip"], ev["http_path"][:80], ts_min)
        if key not in seen:
            seen.add(key)
            deduped.append(ev)

    # Write output
    Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with open(OUTPUT_FILE, "w") as out_f:
        for ev in deduped:
            out_f.write(json.dumps(ev) + "\n")
            written += 1

    save_state({"last_ts": time.time()})
    log.info(
        "nginx parser complete: %d lines parsed, %d skipped, "
        "%d events extracted, %d written after dedup",
        lines_parsed, lines_skipped, len(events), written,
    )


if __name__ == "__main__":
    main()
