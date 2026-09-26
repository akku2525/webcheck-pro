"""
WebCheck Pro - CVE / Vulnerable Component Engine
Author: Akash Mishra

Fingerprints library/CMS/server versions from headers + page source, then
checks the ones we can map to an npm package against the OSV.dev
vulnerability database (https://osv.dev) - free, no API key required.

For components OSV can't help with (WordPress, Drupal, PHP, nginx, Apache -
these live in OS/CMS-specific advisory databases, not npm/OSV) we still
report the disclosed version as a finding, since version disclosure itself
is useful recon info, and flag it for manual CVE lookup (e.g. WPScan,
NVD, vendor advisories).
"""

import re

import requests

REQUEST_TIMEOUT = 8
OSV_API = "https://api.osv.dev/v1/query"

# name -> (regex with one capture group for the version, OSV ecosystem or None, OSV package name or None)
VERSION_PATTERNS = {
    "jQuery":      (r"jquery[/@-]([0-9]+\.[0-9]+\.[0-9]+)", "npm", "jquery"),
    "jQuery UI":   (r"jquery-ui[/-]([0-9]+\.[0-9]+\.[0-9]+)", "npm", "jquery-ui"),
    "Bootstrap":   (r"bootstrap[/@-]([0-9]+\.[0-9]+\.[0-9]+)", "npm", "bootstrap"),
    "Lodash":      (r"lodash[/@.\-]([0-9]+\.[0-9]+\.[0-9]+)", "npm", "lodash"),
    "Vue.js":      (r"vue(?:\.js)?[/@-]([0-9]+\.[0-9]+\.[0-9]+)", "npm", "vue"),
    "Moment.js":   (r"moment[/@-]([0-9]+\.[0-9]+\.[0-9]+)", "npm", "moment"),
    "Axios":       (r"axios[/@-]([0-9]+\.[0-9]+\.[0-9]+)", "npm", "axios"),
    "React":       (r"react(?:-dom)?[/@-]([0-9]+\.[0-9]+\.[0-9]+)", "npm", "react"),
    "Angular":     (r"angular(?:\.js)?[/@-]([0-9]+\.[0-9]+\.[0-9]+)", "npm", "angular"),
    "Handlebars":  (r"handlebars[/@-]([0-9]+\.[0-9]+\.[0-9]+)", "npm", "handlebars"),
    "WordPress":   (r"WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", None, None),
    "Drupal":      (r"Drupal\s+([0-9]+\.[0-9]+)", None, None),
    "PHP":         (r"PHP/([0-9]+\.[0-9]+\.[0-9]+)", None, None),
    "nginx":       (r"nginx/([0-9]+\.[0-9]+\.[0-9]+)", None, None),
    "Apache":      (r"Apache/([0-9]+\.[0-9]+\.[0-9]+)", None, None),
    "OpenSSL":     (r"OpenSSL/([0-9]+\.[0-9]+\.[0-9]+\w*)", None, None),
}


def fingerprint_versions(headers: dict, body: str):
    """Scans headers + HTML source for version strings of known components."""
    haystack = " ".join([f"{k}: {v}" for k, v in (headers or {}).items()]) + " " + (body or "")
    found = {}
    for name, (pattern, ecosystem, pkg) in VERSION_PATTERNS.items():
        m = re.search(pattern, haystack, re.IGNORECASE)
        if m:
            found[name] = {"version": m.group(1), "ecosystem": ecosystem, "osv_package": pkg}
    return found


def _query_osv(package: str, ecosystem: str, version: str):
    try:
        resp = requests.post(
            OSV_API,
            json={"package": {"name": package, "ecosystem": ecosystem}, "version": version},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return {"error": f"OSV.dev returned {resp.status_code}"}
        vulns = resp.json().get("vulns", [])
        results = []
        for v in vulns:
            cve_ids = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            severity = "UNKNOWN"
            for sev in v.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    severity = "SEE CVSS"
            results.append({
                "id": v.get("id"),
                "cve": cve_ids[0] if cve_ids else v.get("id"),
                "summary": (v.get("summary") or v.get("details", ""))[:220],
                "severity": severity,
            })
        return {"vulnerabilities": results}
    except Exception as e:
        return {"error": str(e)}


def cve_lookup(headers: dict, body: str):
    """
    Full pipeline: fingerprint versions -> query OSV.dev for npm-ecosystem
    packages -> return a structured report. Never raises - always returns
    a dict, even on total failure, so it's safe to call directly from the
    scan orchestrator.
    """
    try:
        detected = fingerprint_versions(headers, body)
        report = {}
        for name, info in detected.items():
            entry = {"version": info["version"]}
            if info["ecosystem"] and info["osv_package"]:
                osv_result = _query_osv(info["osv_package"], info["ecosystem"], info["version"])
                entry["source"] = "osv.dev"
                entry.update(osv_result)
            else:
                entry["source"] = "manual review required"
                entry["note"] = ("Version disclosed but not in an OSV-tracked ecosystem "
                                  "(check WPScan / NVD / vendor advisories for known CVEs).")
            report[name] = entry
        return report
    except Exception as e:
        return {"error": str(e)}
