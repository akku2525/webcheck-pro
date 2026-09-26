"""
WebCheck Pro - Threat Intelligence Integration (Shodan / Censys)
Author: Akash Mishra

Both are optional - the tool works fully without API keys. When a key is
supplied (via CLI flag or SHODAN_API_KEY / CENSYS_API_ID / CENSYS_API_SECRET
env vars), we enrich the scan with what these platforms have already
indexed about the target IP: open ports, banners, known CVEs, org info.
"""

import requests

REQUEST_TIMEOUT = 10


def shodan_lookup(ip: str, api_key: str):
    if not api_key:
        return {"skipped": "No Shodan API key provided (use --shodan-key or SHODAN_API_KEY env var)"}
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                          params={"key": api_key}, timeout=REQUEST_TIMEOUT)
        if r.status_code == 404:
            return {"error": "No Shodan data indexed for this IP"}
        if r.status_code == 401:
            return {"error": "Invalid Shodan API key"}
        if r.status_code != 200:
            return {"error": f"Shodan returned HTTP {r.status_code}"}
        data = r.json()
        services = []
        for item in data.get("data", []):
            services.append({
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": (item.get("data") or "").strip().split("\n")[0][:150],
            })
        return {
            "org": data.get("org"),
            "isp": data.get("isp"),
            "os": data.get("os"),
            "hostnames": data.get("hostnames", []),
            "ports": data.get("ports", []),
            "vulns": sorted(data.get("vulns", [])),
            "tags": data.get("tags", []),
            "last_update": data.get("last_update"),
            "services": services,
            "country": data.get("country_name"),
            "city": data.get("city"),
        }
    except Exception as e:
        return {"error": str(e)}


def censys_lookup(ip: str, api_id: str, api_secret: str):
    if not (api_id and api_secret):
        return {"skipped": "No Censys API credentials provided (use --censys-id/--censys-secret or "
                            "CENSYS_API_ID/CENSYS_API_SECRET env vars)"}
    try:
        r = requests.get(f"https://search.censys.io/api/v2/hosts/{ip}",
                          auth=(api_id, api_secret), timeout=REQUEST_TIMEOUT)
        if r.status_code == 404:
            return {"error": "No Censys data indexed for this IP"}
        if r.status_code in (401, 403):
            return {"error": "Invalid Censys API credentials"}
        if r.status_code != 200:
            return {"error": f"Censys returned HTTP {r.status_code}"}
        result = r.json().get("result", {})
        services = []
        for svc in result.get("services", []):
            services.append({
                "port": svc.get("port"),
                "service_name": svc.get("service_name"),
                "transport_protocol": svc.get("transport_protocol"),
                "software": [f"{s.get('product', '')} {s.get('version', '')}".strip()
                             for s in svc.get("software", [])] if svc.get("software") else [],
            })
        loc = result.get("location") or {}
        asn_info = result.get("autonomous_system") or {}
        return {
            "autonomous_system": asn_info.get("name"),
            "asn": asn_info.get("asn"),
            "os": (result.get("operating_system") or {}).get("product"),
            "location": f"{loc.get('city', '')}, {loc.get('country', '')}".strip(", "),
            "services": services,
            "last_updated": result.get("last_updated_at"),
        }
    except Exception as e:
        return {"error": str(e)}
