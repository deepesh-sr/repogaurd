"""L1-L2: security headers + cookie flags from GET /."""
from __future__ import annotations

from repoguard.live.http import LiveClient, evidence
from repoguard.models import Finding
from repoguard.utils.owasp import TOOL_DEFAULT_OWASP

OWASP = TOOL_DEFAULT_OWASP["live"]

HEADER_RULES = [
    # (header, title, severity, fix)
    ("Content-Security-Policy", "Missing Content-Security-Policy header", "Medium",
     "Add a CSP header, e.g. Content-Security-Policy: default-src 'self'."),
    ("Strict-Transport-Security", "Missing HSTS header", "Medium",
     "Add Strict-Transport-Security: max-age=31536000; includeSubDomains (serve over HTTPS)."),
    ("X-Frame-Options", "Missing X-Frame-Options header", "Low",
     "Add X-Frame-Options: DENY (or SAMEORIGIN) to block clickjacking."),
    ("X-Content-Type-Options", "Missing X-Content-Type-Options header", "Low",
     "Add X-Content-Type-Options: nosniff."),
]


def check(base_url: str, client: LiveClient):
    """Return (findings, root_resp_or_None)."""
    resp = client.request("GET", base_url.rstrip("/") + "/")
    if resp is None:
        return [], None
    findings: list[Finding] = []
    lower = {k.lower(): v for k, v in resp.headers.items()}
    is_https = base_url.lower().startswith("https://")
    for header, title, severity, fix in HEADER_RULES:
        if header.lower() not in lower:
            sev = severity
            if header == "Strict-Transport-Security" and not is_https:
                sev = "Low"  # HSTS only meaningful over HTTPS; still worth noting
                fix = "Serve over HTTPS, then " + fix[0].lower() + fix[1:]
            findings.append(Finding(
                id=f"LIVE-HDR-{header.upper().replace('-', '_')}",
                title=title, severity=sev, tool="live",
                where=f"GET {base_url}", evidence=evidence(resp)[:2000],
                owasp=OWASP, fix=fix, endpoint="/", method="GET"))
    # L2: cookies. requests merges multiple Set-Cookie headers into one
    # comma-joined string; split on commas that start a new cookie
    # (comma followed by token+equals before any semicolon) so Expires
    # dates (which contain commas) survive.
    import re
    raw = resp.headers.get("Set-Cookie", "") or ""
    jars = [c.strip() for c in re.split(r",\s*(?=[^;,]*=)", raw) if c.strip()]
    for jar in jars:
        name = jar.split("=", 1)[0].strip() or "cookie"
        low = jar.lower()
        for attr, flag in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")):
            if flag not in low:
                findings.append(Finding(
                    id=f"LIVE-COOKIE-{attr.upper()}-MISSING",
                    title=f"Cookie '{name}' without {attr} flag", severity="Medium",
                    tool="live", where=f"GET {base_url}",
                    evidence=f"Set-Cookie: {jar[:300]}",
                    owasp=OWASP,
                    fix=f"Set {attr} on the cookie (Django: SESSION_COOKIE_{attr.upper()}=True / response.set_cookie(..., {flag}=True)).",
                    endpoint="/", method="GET"))
    return findings, resp
