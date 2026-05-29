#!/usr/bin/env python3
import os
"""
rebuild_geoip_cache.py — Rebuild GeoIP cache from all OpenSearch IPs
Runs hourly to ensure new attacker IPs get resolved immediately.
"""
import json, ssl, base64, urllib.request, sys
import geoip2.database
from pathlib import Path

OPENSEARCH_URL = "https://localhost:9200"
OS_USER = "admin"
OS_PASS = os.environ.get("OPENSEARCH_PASS", "")
ALERT_INDEX = "wazuh-alerts-4.x-*"
CACHE_PATH = "/opt/cowrie-logs/geoip_cache.json"
CITY_DB = "/opt/geoip/GeoLite2-City.mmdb"
ASN_DB  = "/opt/geoip/GeoLite2-ASN.mmdb"

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
AUTH = "Basic " + base64.b64encode(f"{OS_USER}:{OS_PASS}".encode()).decode()

# Load existing cache
try:
    with open(CACHE_PATH) as f:
        cache = json.load(f)
except Exception:
    cache = {}

# Get all unique IPs from OpenSearch
body = json.dumps({
    "size": 0,
    "query": {"exists": {"field": "data.honeypot"}},
    "aggs": {"all_ips": {"terms": {"field": "data.src_ip", "size": 2000}}}
}).encode()
req = urllib.request.Request(
    f"{OPENSEARCH_URL}/{ALERT_INDEX}/_search",
    data=body,
    headers={"Content-Type": "application/json", "Authorization": AUTH},
    method="POST"
)
with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as r:
    result = json.loads(r.read().decode())

buckets = result["aggregations"]["all_ips"]["buckets"]
all_ips = [b["key"] for b in buckets]

# Find new IPs not in cache
new_ips = [ip for ip in all_ips if ip not in cache]

if not new_ips:
    print(f"[+] Cache up to date ({len(cache)} IPs)")
    sys.exit(0)

print(f"[+] Resolving {len(new_ips)} new IPs via MaxMind...")
reader_city = geoip2.database.Reader(CITY_DB)
reader_asn  = geoip2.database.Reader(ASN_DB)

resolved = 0
for ip in new_ips:
    try:
        city = reader_city.city(ip)
        asn  = reader_asn.asn(ip)
        cache[ip] = {
            "country": city.country.name or "",
            "city":    city.city.name or "",
            "org":     asn.autonomous_system_organization or "",
            "asn":     f"AS{asn.autonomous_system_number}" if asn.autonomous_system_number else "",
        }
        resolved += 1
    except Exception:
        cache[ip] = {"country": "", "city": "", "org": "", "asn": ""}

with open(CACHE_PATH, "w") as f:
    json.dump(cache, f)

print(f"[+] Cache updated: {len(cache)} total IPs ({resolved} newly resolved)")
