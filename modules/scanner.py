"""
WebCheck Pro - Recon Engine
Author: Akash Mishra

All individual "checks" live here. Every function is wrapped so that a
failure in one check (timeout, missing record, blocked API, etc.) never
takes down the rest of the scan - it just reports the error inline so the
dashboard still renders with whatever data was collected.
"""

import concurrent.futures
import datetime
import hashlib
import json
import socket
import ssl
import subprocess
import time
from urllib.parse import urlparse

import requests

try:
    import dns.resolver
    import dns.reversename
except ImportError:
    dns = None

try:
    import whois as pywhois
except ImportError:
    pywhois = None

from cryptography import x509
from cryptography.hazmat.backends import default_backend

REQUEST_TIMEOUT = 8
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) WebCheckPro/1.0 (+by Akash Mishra)"

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    587: "SMTP-SUB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 27017: "MongoDB",
}

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "akamai": ["akamai", "x-akamai-transformed"],
    "aws waf / cloudfront": ["x-amz-cf-id", "x-amzn-requestid"],
    "imperva / incapsula": ["x-iinfo", "incap_ses", "visid_incap"],
    "f5 big-ip asm": ["x-waf-event-info", "bigipserver"],
    "fastly": ["x-served-by", "x-fastly-request-id"],
    "wordfence": ["x-wordfence"],
}

TECH_SIGNATURES = {
    "React": ['id="root"', "react-dom", "_reactRootContainer", "data-reactroot"],
    "Vue.js": ["__vue__", "data-v-", "vue.js", "vue.min.js"],
    "Angular": ["ng-version", "ng-app", "angular.js", "angular.min.js"],
    "jQuery": ["jquery.js", "jquery.min.js", "jquery-"],
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Drupal": ["drupal.js", "/sites/default/", "drupal.settings"],
    "Joomla": ["/media/jui/", "joomla"],
    "Next.js": ["__next", "_next/static"],
    "Bootstrap": ["bootstrap.min.css", "bootstrap.css"],
    "Tailwind CSS": ["tailwind"],
    "Lodash": ["lodash.js", "lodash.min.js"],
    "Google Tag Manager": ["googletagmanager.com/gtm.js"],
    "Google Analytics": ["google-analytics.com", "gtag("],
    "Facebook Pixel": ["connect.facebook.net", "fbq("],
    "Shopify": ["cdn.shopify.com", "shopify"],
    "Cloudflare CDN": ["cdnjs.cloudflare.com"],
    "Stripe": ["js.stripe.com"],
    "Sentry": ["sentry.io", "sentry-cdn"],
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS on future visits (HSTS)",
    "Content-Security-Policy": "Mitigates XSS / injection by whitelisting sources",
    "X-Frame-Options": "Protects against clickjacking",
    "X-Content-Type-Options": "Blocks MIME-sniffing attacks",
    "X-XSS-Protection": "Legacy browser XSS filter toggle",
    "Referrer-Policy": "Controls how much referrer info is leaked",
    "Permissions-Policy": "Restricts browser feature/API access",
}


def safe(fn):
    """Decorator: never let one check crash the whole scan."""
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            return {"error": str(e)}
    return wrapper


def normalize_target(target: str):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    return parsed.scheme, parsed.netloc, target


# --------------------------------------------------------------------------
# HTTP / Headers / Cookies
# --------------------------------------------------------------------------

@safe
def fetch_http(url):
    resp = requests.get(
        url, timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        allow_redirects=True, verify=True,
    )
    return {
        "status_code": resp.status_code,
        "final_url": resp.url,
        "headers": dict(resp.headers),
        "cookies": [
            {"name": c.name, "value": (c.value[:24] + "...") if c.value and len(c.value) > 24 else c.value,
             "domain": c.domain, "secure": c.secure, "httponly": bool(c._rest.get("HttpOnly", False))}
            for c in resp.cookies
        ],
        "body": resp.text[:300000],  # cap for tech-stack scanning
        "elapsed_ms": round(resp.elapsed.total_seconds() * 1000, 1),
    }


@safe
def analyze_security_headers(headers: dict):
    headers_lower = {k.lower(): v for k, v in headers.items()}
    results = {}
    present = 0
    for h, desc in SECURITY_HEADERS.items():
        found = h.lower() in headers_lower
        results[h] = {"present": found, "value": headers_lower.get(h.lower(), ""), "desc": desc}
        if found:
            present += 1
    score = round((present / len(SECURITY_HEADERS)) * 100)
    return {"headers": results, "score": score}


@safe
def detect_waf(headers: dict, body_snippet: str = ""):
    headers_str = json.dumps(headers).lower()
    found = []
    for waf, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in headers_str:
                found.append(waf)
                break
    return {"detected": sorted(set(found)) or ["None detected"], "raw_server_header": headers.get("Server", "")}


@safe
def detect_tech_stack(headers: dict, body: str):
    body_lower = (body or "").lower()
    headers_str = json.dumps(headers).lower()
    found = []
    for tech, sigs in TECH_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in body_lower or sig.lower() in headers_str:
                found.append(tech)
                break
    if "X-Powered-By" in headers:
        found.append(f"Powered-By: {headers['X-Powered-By']}")
    return sorted(set(found)) or ["Unable to fingerprint"]


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------

@safe
def dns_records(domain):
    if dns is None:
        return {"error": "dnspython not installed"}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
    results = {}
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(r).strip() for r in answers]
        except Exception:
            results[rtype] = []
    return results


@safe
def dnssec_check(domain):
    if dns is None:
        return {"error": "dnspython not installed"}
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(domain, "DNSKEY")
        return {"enabled": True, "keys": len(answers)}
    except dns.resolver.NoAnswer:
        return {"enabled": False, "keys": 0}
    except Exception as e:
        return {"enabled": False, "error": str(e)}


@safe
def reverse_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)
        return host[0]
    except Exception:
        return "No PTR record"


# --------------------------------------------------------------------------
# WHOIS
# --------------------------------------------------------------------------

@safe
def whois_lookup(domain):
    if pywhois is None:
        return {"error": "python-whois not installed"}
    w = pywhois.whois(domain)

    def fmt(v):
        if isinstance(v, list):
            v = v[0] if v else None
        if isinstance(v, datetime.datetime):
            return v.strftime("%d %B %Y")
        return v

    return {
        "domain_name": fmt(w.get("domain_name")),
        "registrar": fmt(w.get("registrar")),
        "creation_date": fmt(w.get("creation_date")),
        "updated_date": fmt(w.get("updated_date")),
        "expiration_date": fmt(w.get("expiration_date")),
        "name_servers": w.get("name_servers") if isinstance(w.get("name_servers"), list) else [w.get("name_servers")],
        "status": w.get("status"),
        "emails": w.get("emails"),
        "org": fmt(w.get("org")),
        "country": fmt(w.get("country")),
    }


# --------------------------------------------------------------------------
# SSL / TLS
# --------------------------------------------------------------------------

@safe
def ssl_certificate(domain, port=443):
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=REQUEST_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            der = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der, default_backend())

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    now = datetime.datetime.utcnow()
    not_after = cert.not_valid_after
    days_left = (not_after - now).days

    san = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        pass

    return {
        "subject": subject,
        "issuer": issuer,
        "serial_number": format(cert.serial_number, "X"),
        "not_before": cert.not_valid_before.strftime("%d %B %Y"),
        "not_after": not_after.strftime("%d %B %Y"),
        "days_remaining": days_left,
        "expired": days_left < 0,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "version": str(cert.version),
        "subject_alt_names": san,
        "fingerprint_sha256": cert.fingerprint(hashlib.sha256()).hex(),
    }


@safe
def tls_protocol_support(domain, port=443):
    """Best-effort probe of which TLS/SSL protocol versions the server accepts."""
    results = {}
    protocol_map = {
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.0": ssl.TLSVersion.TLSv1,
    }
    for name, version in protocol_map.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((domain, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock.getpeercert()
            results[name] = True
        except Exception:
            results[name] = False
    return results


# --------------------------------------------------------------------------
# Active security probes (CORS, methods, clickjacking, open redirect, takeover)
# --------------------------------------------------------------------------

@safe
def cors_check(url):
    """Sends a spoofed Origin header and inspects the reflected CORS policy."""
    test_origin = "https://webcheck-pro-cors-test.evil-example.com"
    r = requests.get(url, timeout=REQUEST_TIMEOUT,
                      headers={"User-Agent": USER_AGENT, "Origin": test_origin},
                      allow_redirects=True)
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    reflects_arbitrary_origin = acao == test_origin or acao == "*"
    misconfigured = reflects_arbitrary_origin and acac.lower() == "true"
    return {
        "access_control_allow_origin": acao or "not set",
        "access_control_allow_credentials": acac or "not set",
        "reflects_arbitrary_origin": reflects_arbitrary_origin,
        "misconfigured": misconfigured,
    }


@safe
def http_methods_check(url):
    r = requests.options(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
    allow = r.headers.get("Allow", "")
    methods = [m.strip() for m in allow.split(",") if m.strip()]
    risky = [m for m in methods if m.upper() in ("PUT", "DELETE", "TRACE", "CONNECT")]
    return {"status_code": r.status_code, "allowed_methods": methods or ["Unknown (no Allow header)"], "risky_methods": risky}


@safe
def clickjacking_check(headers: dict):
    headers_lower = {k.lower(): v for k, v in headers.items()}
    xfo = headers_lower.get("x-frame-options")
    csp = headers_lower.get("content-security-policy", "")
    frame_ancestors = "frame-ancestors" in csp.lower()
    protected = bool(xfo) or frame_ancestors
    return {
        "protected": protected,
        "x_frame_options": xfo or "not set",
        "csp_frame_ancestors": frame_ancestors,
    }


@safe
def open_redirect_probe(url):
    """Non-destructive check: appends common redirect params pointing at a
    harmless external test domain and sees whether the server 30x-redirects
    there without validation."""
    test_target = "https://webcheck-pro-redirect-test.evil-example.com"
    params = ["next", "url", "redirect", "redirect_uri", "return", "returnUrl", "dest", "continue"]
    base = url.split("?")[0]
    findings = []
    for p in params[:6]:  # keep it fast
        try:
            test_url = f"{base}?{p}={test_target}"
            r = requests.get(test_url, timeout=5, allow_redirects=False, headers={"User-Agent": USER_AGENT})
            location = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308) and test_target in location:
                findings.append({"param": p, "status_code": r.status_code, "location": location})
        except Exception:
            continue
    return {"vulnerable_params": findings, "tested_params": params[:6]}


TAKEOVER_FINGERPRINTS = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "s3.amazonaws.com": "AWS S3 Bucket",
    "azurewebsites.net": "Azure Web App",
    "cloudapp.net": "Azure Cloud Service",
    "shopify.com": "Shopify",
    "unbouncepages.com": "Unbounce",
    "wpengine.com": "WP Engine",
    "fastly.net": "Fastly",
    "zendesk.com": "Zendesk",
    "surge.sh": "Surge.sh",
    "readme.io": "ReadMe.io",
}


@safe
def subdomain_takeover_check(subdomains, max_check=25):
    """For each discovered subdomain, checks if its CNAME points at a
    third-party service but the subdomain itself fails to resolve /
    returns an error page - a classic takeover indicator."""
    if not isinstance(subdomains, list):
        return {"error": "no subdomains to check"}
    if dns is None:
        return {"error": "dnspython not installed"}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    suspicious = []
    for sub in subdomains[:max_check]:
        try:
            answers = resolver.resolve(sub, "CNAME")
            cname = str(answers[0].target).rstrip(".")
            service = next((v for k, v in TAKEOVER_FINGERPRINTS.items() if k in cname), None)
            if service:
                try:
                    resolver.resolve(sub, "A")
                    resolves = True
                except Exception:
                    resolves = False
                if not resolves:
                    suspicious.append({"subdomain": sub, "cname": cname, "service": service})
        except Exception:
            continue
    return {"checked": min(len(subdomains), max_check), "suspicious": suspicious}


@safe
def dns_zone_transfer(domain, nameservers):
    """Attempts an AXFR zone transfer against each authoritative nameserver.
    A properly configured DNS server will refuse this - if it succeeds,
    it's a serious information-disclosure vulnerability."""
    if dns is None:
        return {"error": "dnspython not installed"}
    import dns.query
    import dns.zone
    results = {}
    ns_list = nameservers if isinstance(nameservers, list) else []
    for ns in ns_list[:5]:
        ns_clean = ns.rstrip(".")
        try:
            ns_ip = socket.gethostbyname(ns_clean)
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5, lifetime=5))
            records = list(z.nodes.keys())
            results[ns_clean] = {"vulnerable": True, "record_count": len(records)}
        except Exception:
            results[ns_clean] = {"vulnerable": False}
    return results


@safe
def email_harvest(body: str):
    import re
    emails = set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", body or ""))
    junk = ("example.com", "sentry.io", ".png", ".jpg", "w3.org", "schema.org")
    clean = sorted(e for e in emails if not any(j in e.lower() for j in junk))
    return clean[:25]


@safe
def banner_grab(ip, ports_info, timeout=2):
    """Grabs a service banner from each open port (best-effort, non-intrusive)."""
    if not isinstance(ports_info, list):
        return {}
    banners = {}
    for p in ports_info:
        port = p["port"]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                if port in (80, 8080, 8443, 443):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(256).decode(errors="ignore").strip().replace("\r\n", " | ")
                if banner:
                    banners[port] = banner[:120]
        except Exception:
            continue
    return banners


COMMON_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel", "whm",
    "autodiscover", "autoconfig", "m", "shop", "blog", "dev", "test", "staging",
    "api", "app", "portal", "admin", "vpn", "remote", "cdn", "static", "assets",
    "img", "images", "secure", "login", "signin", "sso", "auth", "docs", "help",
    "support", "status", "beta", "demo", "dashboard", "cloud", "git", "gitlab",
    "jenkins", "jira", "confluence", "db", "mysql", "sql", "backup", "old", "new",
]


@safe
def subdomain_bruteforce(domain, wordlist=None, threads=25):
    if dns is None:
        return {"error": "dnspython not installed"}
    wordlist = wordlist or COMMON_SUBDOMAIN_WORDLIST
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    def _try(sub):
        fqdn = f"{sub}.{domain}"
        try:
            resolver.resolve(fqdn, "A")
            return fqdn
        except Exception:
            return None

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for result in ex.map(_try, wordlist):
            if result:
                found.append(result)
    return sorted(set(found))


SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.DS_Store", "/wp-config.php.bak",
    "/config.php.bak", "/backup.zip", "/backup.sql", "/phpinfo.php",
    "/.svn/entries", "/.htaccess", "/server-status", "/.aws/credentials",
    "/id_rsa", "/composer.json", "/package.json", "/.npmrc", "/web.config",
]


@safe
def sensitive_paths_check(base_url, deep=False):
    """Passive GET-only probe for commonly-exposed sensitive files (no
    directory brute-forcing of arbitrary paths - just a short, well-known
    list). A short list runs in fast mode; the full list runs with --deep."""
    paths = SENSITIVE_PATHS if deep else SENSITIVE_PATHS[:6]
    base = base_url.rstrip("/")

    def _check(path):
        try:
            r = requests.get(base + path, timeout=5, headers={"User-Agent": USER_AGENT}, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                return {"path": path, "status_code": r.status_code, "size": len(r.content)}
        except Exception:
            return None
        return None

    exposed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for result in ex.map(_check, paths):
            if result:
                exposed.append(result)
    return {"tested": len(paths), "exposed": exposed}


@safe
def sri_check(body, target_domain):
    """Flags cross-origin <script>/<link> tags loaded without a
    Subresource Integrity (integrity=...) attribute - OWASP A08."""
    import re
    if not body:
        return {"scripts_checked": 0, "missing_sri": []}
    tags = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"'][^>]*>", body, re.IGNORECASE)
    missing = []
    for src in tags:
        if not src.startswith("http"):
            continue  # relative/same-origin script, SRI not required
        if target_domain in src:
            continue  # same-origin
        tag_match = re.search(re.escape(src), body)
        # look at the whole tag text for an integrity attribute
        tag_start = body.rfind("<script", 0, tag_match.start()) if tag_match else -1
        tag_end = body.find(">", tag_start) if tag_start != -1 else -1
        tag_text = body[tag_start:tag_end] if tag_start != -1 and tag_end != -1 else ""
        if "integrity=" not in tag_text.lower():
            missing.append(src)
    return {"scripts_checked": len(tags), "missing_sri": sorted(set(missing))[:15]}


# --------------------------------------------------------------------------
# Geo / ASN / Server info
# --------------------------------------------------------------------------

@safe
def resolve_ip(domain):
    return socket.gethostbyname(domain)


@safe
def geo_ip_lookup(ip):
    r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,"
                      f"city,zip,lat,lon,timezone,isp,org,as,asname,query",
                      timeout=REQUEST_TIMEOUT)
    data = r.json()
    if data.get("status") != "success":
        return {"error": data.get("message", "lookup failed")}
    return data


# --------------------------------------------------------------------------
# Subdomains (certificate transparency)
# --------------------------------------------------------------------------

@safe
def subdomains_crtsh(domain):
    r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
    if r.status_code != 200:
        return {"error": f"crt.sh returned {r.status_code}"}
    entries = r.json()
    names = set()
    for e in entries:
        for n in e.get("name_value", "").split("\n"):
            n = n.strip().lower()
            if n and not n.startswith("*."):
                names.add(n)
    return sorted(names)[:60]


# --------------------------------------------------------------------------
# robots.txt / security.txt
# --------------------------------------------------------------------------

@safe
def fetch_text_file(base_url, path):
    r = requests.get(base_url.rstrip("/") + path, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
    if r.status_code == 200:
        return {"present": True, "content": r.text[:4000]}
    return {"present": False, "status_code": r.status_code}


# --------------------------------------------------------------------------
# Port scan
# --------------------------------------------------------------------------

def _check_port(ip, port, timeout=1.2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return port, result == 0
    except Exception:
        return port, False


@safe
def port_scan(ip, ports=None):
    ports = ports or list(COMMON_PORTS.keys())
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = [ex.submit(_check_port, ip, p) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            port, is_open = f.result()
            if is_open:
                open_ports.append({"port": port, "service": COMMON_PORTS.get(port, "unknown")})
    return sorted(open_ports, key=lambda x: x["port"])


# --------------------------------------------------------------------------
# Traceroute
# --------------------------------------------------------------------------

@safe
def traceroute(host, max_hops=15):
    try:
        proc = subprocess.run(
            ["traceroute", "-m", str(max_hops), "-w", "1", "-q", "1", host],
            capture_output=True, text=True, timeout=30,
        )
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        return lines[1:] if len(lines) > 1 else lines
    except FileNotFoundError:
        return {"error": "traceroute binary not found (install: sudo apt install traceroute)"}
    except subprocess.TimeoutExpired:
        return {"error": "traceroute timed out"}


# --------------------------------------------------------------------------
# HSTS check
# --------------------------------------------------------------------------

@safe
def hsts_check(headers: dict):
    headers_lower = {k.lower(): v for k, v in headers.items()}
    hsts = headers_lower.get("strict-transport-security")
    if not hsts:
        return {"enabled": False}
    max_age = 0
    for part in hsts.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age"):
            try:
                max_age = int(part.split("=")[1])
            except Exception:
                pass
    return {
        "enabled": True,
        "raw": hsts,
        "max_age": max_age,
        "includeSubDomains": "includesubdomains" in hsts.lower(),
        "preload": "preload" in hsts.lower(),
    }


# --------------------------------------------------------------------------
# Quality score
# --------------------------------------------------------------------------

def compute_quality_score(sec_headers_score, hsts_enabled, ssl_valid, waf_detected, dnssec_enabled):
    score = 0
    score += min(sec_headers_score, 100) * 0.4
    score += 20 if hsts_enabled else 0
    score += 20 if ssl_valid else 0
    score += 10 if waf_detected else 0
    score += 10 if dnssec_enabled else 0
    return round(min(score, 100))


# --------------------------------------------------------------------------
# Master orchestrator (parallelized)
# --------------------------------------------------------------------------

def run_full_scan(target: str, progress_cb=None, deep=False, threads=20,
                   shodan_key=None, censys_id=None, censys_secret=None,
                   screenshot=False):
    """
    deep=False (default): fast mode - skips subdomain bruteforce, zone
        transfer attempts, open-redirect probing, and the full sensitive-path
        list to keep scans quick.
    deep=True: full active recon - adds subdomain bruteforce, AXFR zone
        transfer attempts, open-redirect probing, banner grabbing, and the
        full sensitive-path exposure list.
    shodan_key / censys_id+censys_secret: optional threat-intel enrichment.
    screenshot: capture a headless-Chromium screenshot of the target.
    """
    from modules import cve as cve_mod
    from modules import threat_intel
    from modules import owasp as owasp_mod
    from modules import screenshot as screenshot_mod

    done = {"n": 0}
    lock_total = 27 if deep else 22

    def report(step):
        done["n"] += 1
        if progress_cb:
            progress_cb(step, done["n"], lock_total)

    scheme, netloc, full_url = normalize_target(target)
    domain_www_stripped = netloc.split(":")[0]

    data = {
        "target": target, "url": full_url, "domain": domain_www_stripped,
        "scan_time": datetime.datetime.utcnow().strftime("%d %B %Y, %H:%M UTC"),
        "deep_scan": deep,
    }

    # ---- Stage 1: things everything else depends on ----
    report("Resolving IP address")
    data["ip"] = resolve_ip(domain_www_stripped)

    report("Fetching HTTP response & headers")
    data["http"] = fetch_http(full_url)
    headers = data["http"].get("headers", {}) if isinstance(data["http"], dict) else {}
    body = data["http"].get("body", "") if isinstance(data["http"], dict) else ""

    report("Querying DNS records")
    data["dns"] = dns_records(domain_www_stripped)

    # ---- Stage 2: run every independent check concurrently ----
    ip_ok = isinstance(data["ip"], str)
    name_servers = data["dns"].get("NS", []) if isinstance(data["dns"], dict) else []

    jobs = {
        "security_headers": lambda: analyze_security_headers(headers),
        "hsts": lambda: hsts_check(headers),
        "waf": lambda: detect_waf(headers, body),
        "tech_stack": lambda: detect_tech_stack(headers, body),
        "dnssec": lambda: dnssec_check(domain_www_stripped),
        "whois": lambda: whois_lookup(domain_www_stripped),
        "ssl": lambda: ssl_certificate(domain_www_stripped),
        "tls_protocols": lambda: tls_protocol_support(domain_www_stripped),
        "geoip": (lambda: geo_ip_lookup(data["ip"])) if ip_ok else (lambda: {"error": "no IP resolved"}),
        "subdomains": lambda: subdomains_crtsh(domain_www_stripped),
        "robots_txt": lambda: fetch_text_file(full_url, "/robots.txt"),
        "security_txt": lambda: (fetch_text_file(full_url, "/.well-known/security.txt")
                                  if fetch_text_file(full_url, "/.well-known/security.txt").get("present")
                                  else fetch_text_file(full_url, "/security.txt")),
        "port_scan": (lambda: port_scan(data["ip"])) if ip_ok else (lambda: {"error": "no IP resolved"}),
        "traceroute": lambda: traceroute(domain_www_stripped),
        "cors": lambda: cors_check(full_url),
        "http_methods": lambda: http_methods_check(full_url),
        "clickjacking": lambda: clickjacking_check(headers),
        "email_harvest": lambda: email_harvest(body),
        "sensitive_paths": lambda: sensitive_paths_check(full_url, deep=deep),
        "sri": lambda: sri_check(body, domain_www_stripped),
        "cve_report": lambda: cve_mod.cve_lookup(headers, body),
        "shodan": (lambda: threat_intel.shodan_lookup(data["ip"], shodan_key)) if ip_ok
                  else (lambda: {"error": "no IP resolved"}),
        "censys": (lambda: threat_intel.censys_lookup(data["ip"], censys_id, censys_secret)) if ip_ok
                  else (lambda: {"error": "no IP resolved"}),
    }
    if deep:
        jobs["subdomain_bruteforce"] = lambda: subdomain_bruteforce(domain_www_stripped, threads=threads)
        jobs["zone_transfer"] = lambda: dns_zone_transfer(domain_www_stripped, name_servers)
        jobs["open_redirect"] = lambda: open_redirect_probe(full_url)
    if screenshot:
        jobs["screenshot"] = lambda: screenshot_mod.capture_screenshot(full_url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, len(jobs))) as ex:
        future_map = {ex.submit(fn): name for name, fn in jobs.items()}
        for future in concurrent.futures.as_completed(future_map):
            name = future_map[future]
            report(name.replace("_", " ").title())
            try:
                data[name] = future.result()
            except Exception as e:
                data[name] = {"error": str(e)}

    # ---- Stage 3: checks that depend on stage-2 results ----
    report("Cross-referencing subdomain takeover risk")
    merged_subs = list(data.get("subdomains") or [])
    if deep and isinstance(data.get("subdomain_bruteforce"), list):
        merged_subs = sorted(set(merged_subs) | set(data["subdomain_bruteforce"]))
    data["subdomains_all"] = merged_subs
    data["subdomain_takeover"] = subdomain_takeover_check(merged_subs)

    if deep and ip_ok and isinstance(data.get("port_scan"), list):
        report("Grabbing service banners")
        data["banners"] = banner_grab(data["ip"], data["port_scan"])
    else:
        data["banners"] = {}

    report("Computing quality score")
    ssl_valid = isinstance(data["ssl"], dict) and "error" not in data["ssl"] and not data["ssl"].get("expired", True)
    waf_ok = isinstance(data["waf"], dict) and data["waf"].get("detected") != ["None detected"]
    dnssec_ok = isinstance(data["dnssec"], dict) and data["dnssec"].get("enabled")
    sec_score = data["security_headers"].get("score", 0) if isinstance(data["security_headers"], dict) else 0
    hsts_ok = isinstance(data["hsts"], dict) and data["hsts"].get("enabled")
    data["quality_score"] = compute_quality_score(sec_score, hsts_ok, ssl_valid, waf_ok, dnssec_ok)

    report("Building findings report")
    from modules.findings import build_findings
    data["findings"] = build_findings(data)

    report("Mapping findings to OWASP Top 10")
    data["owasp"] = owasp_mod.build_owasp_mapping(data["findings"]["list"])

    report("Scan complete")
    return data
