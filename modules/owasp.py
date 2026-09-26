"""
WebCheck Pro - OWASP Top 10 (2021) Mapping Engine
Author: Akash Mishra

Maps every finding the scan already produced onto the OWASP Top 10 (2021)
categories, so the report reads the way a client/auditor expects. Categories
that fundamentally require dynamic/manual testing (real injection attempts,
business-logic review, auth-flow testing, log review, SSRF probing) are NOT
auto-tested here - that would mean shipping exploit tooling. Instead they're
clearly labeled "not assessed by passive/light-active recon" so the report
never implies a false sense of completeness.
"""

OWASP_TOP10_2021 = [
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable & Outdated Components"),
    ("A07:2021", "Identification & Authentication Failures"),
    ("A08:2021", "Software & Data Integrity Failures"),
    ("A09:2021", "Security Logging & Monitoring Failures"),
    ("A10:2021", "Server-Side Request Forgery (SSRF)"),
]

# finding["category"] -> OWASP id. Anything not listed here is simply not shown
# under any OWASP bucket (still visible in the main Findings panel).
CATEGORY_TO_OWASP = {
    "CORS": "A01:2021",
    "HTTP Methods": "A01:2021",
    "Open Redirect": "A01:2021",
    "Sensitive Path Exposure": "A01:2021",
    "SSL/TLS": "A02:2021",
    "Transport Security": "A02:2021",
    "HTTP Headers": "A05:2021",
    "Clickjacking": "A05:2021",
    "DNS": "A05:2021",
    "Infrastructure": "A05:2021",
    "Network Exposure": "A05:2021",
    "Subdomain Takeover": "A05:2021",
    "Best Practice": "A05:2021",
    "Vulnerable Components": "A06:2021",
    "Subresource Integrity": "A08:2021",
    "Information Disclosure": "A01:2021",
    "Threat Intelligence": "A05:2021",
}

# Categories with no reliable passive/light-active signal - shown with an
# honest "requires manual testing" note rather than silently omitted.
MANUAL_TESTING_NOTES = {
    "A03:2021": "SQL/command/XSS injection requires active payload testing "
                "(e.g. Burp Suite, OWASP ZAP active scan, sqlmap) against "
                "specific input fields - out of scope for passive/OSINT recon.",
    "A04:2021": "Insecure design flaws (business-logic flows, missing rate "
                "limits, trust-boundary issues) require manual architecture "
                "and code review.",
    "A07:2021": "Auth/session flaws (weak password policy, broken MFA, "
                "session fixation) require testing the actual login/auth "
                "flow with valid test credentials.",
    "A09:2021": "Logging & monitoring gaps can't be assessed externally - "
                "requires access to the app's logging/alerting configuration.",
    "A10:2021": "SSRF requires actively submitting attacker-controlled URLs "
                "to server-side fetch functionality - not performed by this "
                "passive/light-active scanner.",
}


def build_owasp_mapping(findings_list):
    buckets = {oid: {"name": name, "findings": [], "note": MANUAL_TESTING_NOTES.get(oid)}
               for oid, name in OWASP_TOP10_2021}

    for f in findings_list or []:
        oid = CATEGORY_TO_OWASP.get(f.get("category"))
        if oid:
            buckets[oid]["findings"].append(f)

    ordered = [{"id": oid, **buckets[oid]} for oid, _ in OWASP_TOP10_2021]
    return ordered
