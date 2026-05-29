#!/usr/bin/env python3
import os
import json, glob, ssl, base64, urllib.request

OPENSEARCH_URL = "https://localhost:9200"
OS_USER  = "admin"
OS_PASS  = os.environ.get("OPENSEARCH_PASS", "")
ALERT_INDEX = "wazuh-alerts-4.x-*"
CACHE_PATH  = "/opt/cowrie-logs/geoip_cache.json"
MMDB_DIRS   = ["/opt/geoip", "/opt/cowrie-tools/pipeline", "/usr/share/GeoIP"]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
AUTH = "Basic " + base64.b64encode(f"{OS_USER}:{OS_PASS}".encode()).decode()

def os_query(path, body):
    req = urllib.request.Request(
        f"{OPENSEARCH_URL}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type":"application/json","Authorization":AUTH},
        method="POST")
    with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
        return json.loads(r.read().decode())

try:
    with open(CACHE_PATH) as f:
        cache = json.load(f)
except Exception:
    cache = {}

result = os_query(f"/{ALERT_INDEX}/_search", {
    "size": 0,
    "query": {"exists": {"field": "data.honeypot"}},
    "aggs": {"all_ips": {"terms": {"field": "data.src_ip", "size": 5000}}}
})
all_ips = [b["key"] for b in result.get("aggregations",{}).get("all_ips",{}).get("buckets",[])]
missing = [ip for ip in all_ips if ip not in cache or not cache[ip].get("country")]
print(f"[+] Total IPs: {len(all_ips)} | Cached: {len(cache)} | Missing: {len(missing)}")

if not missing:
    print("[+] All IPs resolved")
    exit(0)

city_db = asn_db = None
for d in MMDB_DIRS:
    c = glob.glob(f"{d}/GeoLite2-City*.mmdb")
    a = glob.glob(f"{d}/GeoLite2-ASN*.mmdb")
    if c: city_db = c[0]
    if a: asn_db  = a[0]
    if city_db and asn_db: break

if not city_db:
    print("[-] MaxMind databases not found")
    exit(1)

import geoip2.database
city_reader = geoip2.database.Reader(city_db)
asn_reader  = geoip2.database.Reader(asn_db)
resolved = skipped = 0

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
        cache[ip] = {"country":"","city":"","org":""}
        skipped += 1

city_reader.close()
asn_reader.close()

with open(CACHE_PATH, 'w') as f:
    json.dump(cache, f)

print(f"[+] Done: {resolved} resolved, {skipped} no data | Cache: {len(cache)} IPs")
