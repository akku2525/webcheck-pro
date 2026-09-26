"""
WebCheck Pro - Findings Engine
Author: Akash Mishra

Takes the raw scan `data` dict and distills it into a prioritized,
severity-tagged findings list (CRITICAL / HIGH / MEDIUM / LOW / INFO) -
the "so what" summary a pentester actually wants at the top of the report.
"""

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

RISKY_PORTS = {
    21: ("FTP", "MEDIUM"), 23: ("Telnet - unencrypted remote access", "HIGH"),
    3306: ("MySQL exposed to internet", "HIGH"), 3389: ("RDP exposed to internet", "HIGH"),
    5432: ("PostgreSQL exposed to internet", "HIGH"), 6379: ("Redis exposed (often no auth)", "HIGH"),
    27017: ("MongoDB exposed to internet", "HIGH"), 445: ("SMB exposed to internet", "HIGH"),
    22: ("SSH exposed to internet", "LOW"),
}


def _add(findings, severity, title, detail, category):
    findings.append({"severity": severity, "title": title, "detail": detail, "category": category})


def build_findings(data: dict):
    findings = []

    # --- SSL / TLS ---
    ssl_data = data.get("ssl") or {}
    if isinstance(ssl_data, dict) and "error" not in ssl_data:
        if ssl_data.get("expired"):
            _add(findings, "CRITICAL", "SSL certificate has expired",
                 f"Certificate expired on {ssl_data.get('not_after')}. Browsers will show hard warnings to every visitor.",
                 "SSL/TLS")
        elif isinstance(ssl_data.get("days_remaining"), int) and ssl_data["days_remaining"] < 14:
            _add(findings, "HIGH", "SSL certificate expiring very soon",
                 f"Only {ssl_data['days_remaining']} day(s) left before expiry. Renew immediately.", "SSL/TLS")
        elif isinstance(ssl_data.get("days_remaining"), int) and ssl_data["days_remaining"] < 30:
            _add(findings, "MEDIUM", "SSL certificate expiring soon",
                 f"{ssl_data['days_remaining']} day(s) remaining. Schedule renewal.", "SSL/TLS")
    elif isinstance(ssl_data, dict) and "error" in ssl_data:
        _add(findings, "MEDIUM", "Could not retrieve SSL certificate",
             ssl_data.get("error", "unknown error"), "SSL/TLS")

    tls = data.get("tls_protocols") or {}
    if isinstance(tls, dict) and "error" not in tls:
        if tls.get("TLSv1.0") or tls.get("TLSv1.1"):
            legacy = [p for p in ("TLSv1.0", "TLSv1.1") if tls.get(p)]
            _add(findings, "HIGH", "Deprecated TLS protocol versions supported",
                 f"Server still accepts {', '.join(legacy)}. These are broken/deprecated - disable them.", "SSL/TLS")
        if not tls.get("TLSv1.3"):
            _add(findings, "LOW", "TLSv1.3 not supported",
                 "Server doesn't offer the latest, fastest and most secure TLS version.", "SSL/TLS")

    # --- HSTS ---
    hsts = data.get("hsts") or {}
    if not hsts.get("enabled"):
        _add(findings, "MEDIUM", "HSTS not enabled",
             "Without Strict-Transport-Security, users can be downgraded to plain HTTP by an attacker (SSL-stripping).",
             "Transport Security")
    elif hsts.get("max_age", 0) < 15552000:  # < 180 days
        _add(findings, "LOW", "HSTS max-age is short",
             f"max-age={hsts.get('max_age')} seconds. Recommend >= 31536000 (1 year) with preload.", "Transport Security")

    # --- Security headers ---
    sec_headers = (data.get("security_headers") or {}).get("headers", {})
    if isinstance(sec_headers, dict):
        for h, info in sec_headers.items():
            if not info.get("present"):
                sev = "MEDIUM" if h in ("Content-Security-Policy", "X-Frame-Options") else "LOW"
                _add(findings, sev, f"Missing {h} header", info.get("desc", ""), "HTTP Headers")

    # --- Clickjacking ---
    ck = data.get("clickjacking") or {}
    if isinstance(ck, dict) and not ck.get("protected") and "error" not in ck:
        _add(findings, "MEDIUM", "Site can be framed (clickjacking risk)",
             "No X-Frame-Options and no CSP frame-ancestors directive - the page can be embedded in a malicious iframe.",
             "Clickjacking")

    # --- CORS ---
    cors = data.get("cors") or {}
    if isinstance(cors, dict) and cors.get("misconfigured"):
        _add(findings, "HIGH", "Misconfigured CORS policy",
             f"Server reflects arbitrary Origin ({cors.get('access_control_allow_origin')}) "
             f"AND allows credentials - this lets any website read authenticated responses.", "CORS")
    elif isinstance(cors, dict) and cors.get("reflects_arbitrary_origin"):
        _add(findings, "LOW", "CORS reflects arbitrary origins",
             "Access-Control-Allow-Origin reflects any Origin sent, though credentials aren't allowed. Still worth reviewing.",
             "CORS")

    # --- HTTP methods ---
    methods = data.get("http_methods") or {}
    if isinstance(methods, dict) and methods.get("risky_methods"):
        _add(findings, "MEDIUM", "Potentially risky HTTP methods enabled",
             f"Server advertises: {', '.join(methods['risky_methods'])}. Disable if not explicitly required.", "HTTP Methods")

    # --- DNSSEC ---
    dnssec = data.get("dnssec") or {}
    if isinstance(dnssec, dict) and not dnssec.get("enabled"):
        _add(findings, "LOW", "DNSSEC not enabled",
             "DNS responses for this domain aren't cryptographically signed, leaving it open to spoofing/cache-poisoning.",
             "DNS")

    # --- Zone transfer ---
    zt = data.get("zone_transfer")
    if isinstance(zt, dict):
        for ns, result in zt.items():
            if isinstance(result, dict) and result.get("vulnerable"):
                _add(findings, "CRITICAL", f"DNS zone transfer (AXFR) allowed on {ns}",
                     f"Nameserver leaked {result.get('record_count')} DNS records to an unauthenticated request. "
                     f"This exposes your entire DNS zone / internal hostnames.", "DNS")

    # --- Subdomain takeover ---
    takeover = data.get("subdomain_takeover") or {}
    if isinstance(takeover, dict):
        for s in takeover.get("suspicious", []):
            _add(findings, "HIGH", f"Possible subdomain takeover: {s['subdomain']}",
                 f"CNAME points to {s['cname']} ({s['service']}) but doesn't resolve - the service slot may be unclaimed "
                 f"and takeable by an attacker.", "Subdomain Takeover")

    # --- Open redirect ---
    redirect = data.get("open_redirect") or {}
    if isinstance(redirect, dict):
        for f in redirect.get("vulnerable_params", []):
            _add(findings, "MEDIUM", f"Open redirect via '{f['param']}' parameter",
                 f"Unvalidated redirect to attacker-controlled URLs - useful for phishing. ({f['status_code']} -> {f['location']})",
                 "Open Redirect")

    # --- WAF ---
    waf = data.get("waf") or {}
    if isinstance(waf, dict) and waf.get("detected") == ["None detected"]:
        _add(findings, "INFO", "No WAF / CDN protection detected",
             "No known WAF/CDN signature found in headers. Consider Cloudflare/AWS WAF for an extra layer of defense.",
             "Infrastructure")

    # --- Exposed risky ports ---
    ports = data.get("port_scan")
    if isinstance(ports, list):
        for p in ports:
            if p["port"] in RISKY_PORTS:
                label, sev = RISKY_PORTS[p["port"]]
                _add(findings, sev, f"Port {p['port']} ({p['service']}) open to the internet",
                     label, "Network Exposure")

    # --- security.txt (informational) ---
    if not (data.get("security_txt") or {}).get("present"):
        _add(findings, "INFO", "No security.txt published",
             "Publishing /.well-known/security.txt helps researchers report vulnerabilities responsibly.", "Best Practice")

    # --- Emails harvested ---
    emails = data.get("email_harvest")
    if isinstance(emails, list) and emails:
        _add(findings, "INFO", f"{len(emails)} email address(es) exposed on the page",
             ", ".join(emails[:5]) + (", ..." if len(emails) > 5 else ""), "Information Disclosure")

    # --- Sensitive file/path exposure ---
    sp = data.get("sensitive_paths") or {}
    if isinstance(sp, dict):
        for e in sp.get("exposed", []):
            sev = "CRITICAL" if e["path"] in ("/.env", "/.git/config", "/.aws/credentials", "/id_rsa") else "HIGH"
            _add(findings, sev, f"Sensitive file exposed: {e['path']}",
                 f"Publicly accessible (HTTP {e['status_code']}, {e['size']} bytes). "
                 f"May leak credentials, source code, or config secrets.", "Sensitive Path Exposure")

    # --- Missing Subresource Integrity ---
    sri = data.get("sri") or {}
    if isinstance(sri, dict) and sri.get("missing_sri"):
        _add(findings, "LOW", "Cross-origin scripts loaded without Subresource Integrity (SRI)",
             f"{len(sri['missing_sri'])} external script(s) have no integrity attribute - if the CDN is "
             f"compromised, malicious JS would load silently. Example: {sri['missing_sri'][0]}",
             "Subresource Integrity")

    # --- CVEs from fingerprinted component versions ---
    cve_report = data.get("cve_report") or {}
    if isinstance(cve_report, dict) and "error" not in cve_report:
        for component, info in cve_report.items():
            vulns = info.get("vulnerabilities") or []
            if vulns:
                cve_names = ", ".join(v.get("cve") or v.get("id", "?") for v in vulns[:4])
                more = f" (+{len(vulns) - 4} more)" if len(vulns) > 4 else ""
                _add(findings, "HIGH", f"Vulnerable component: {component} {info.get('version', '')}",
                     f"{len(vulns)} known vulnerabilities via OSV.dev: {cve_names}{more}", "Vulnerable Components")

    # --- Shodan-known vulnerabilities ---
    shodan = data.get("shodan") or {}
    if isinstance(shodan, dict) and shodan.get("vulns"):
        _add(findings, "CRITICAL", f"{len(shodan['vulns'])} known CVE(s) flagged by Shodan for this host",
             ", ".join(shodan["vulns"][:8]) + (", ..." if len(shodan["vulns"]) > 8 else ""),
             "Threat Intelligence")

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] += 1

    return {"list": findings, "counts": counts, "total": len(findings)}
