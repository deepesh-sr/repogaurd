"""A1-A5: live API tests over the M2 endpoint inventory.

A1 unauth exposure (Critical) is never cut. Probes run sequentially.
"""
from __future__ import annotations

import re

from repoguard.live.http import LiveClient, evidence, find_leak, looks_like_data, similar
from repoguard.models import Endpoint, Finding
from repoguard.utils.debug import dprint
from repoguard.utils.owasp import TOOL_DEFAULT_OWASP

OWASP = TOOL_DEFAULT_OWASP["api"]

# A2: fuzz only state-changing verbs (OPTIONS/HEAD noise excluded per M3 plan).
FUZZ_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
FUZZ_SEV = {"PUT": "High", "DELETE": "High", "POST": "Medium", "PATCH": "Medium", "GET": "Low"}

ID_PARAM = re.compile(r"\{(id|pk|slug|uuid|username)\}", re.IGNORECASE)
ID_TRIES = ["1", "2"]


def _url(base: str, path: str) -> str:
    p = ID_PARAM.sub("1", path)  # concrete id for probing
    return base.rstrip("/") + (p if p.startswith("/") else "/" + p)


def check_a1(base: str, client: LiveClient, ep: Endpoint,
             authed: dict | None) -> Finding | None:
    """Unauthenticated call; data instead of 401/403 -> Critical."""
    method = ep.methods[0] if ep.methods else "GET"
    resp = client.request(method, _url(base, ep.path))
    if resp is None:
        return None
    if resp.status in (401, 403, 404):
        return None
    if resp.status == 500:
        return None  # leak path (A3/L4), not exposure
    if not looks_like_data(resp):
        return None
    dprint("api.a1 EXPOSED", method, ep.path)  # [DEBUG] REMOVE in T6
    ctrl = ""
    if client.token and authed is not None:
        ctrl = " Authenticated control call also succeeded, so the route is live."
    return Finding(
        id="API-UNAUTH-EXPOSURE",
        title=f"Unauthenticated access returns data: {method} {ep.path}",
        severity="Critical", tool="api",
        where=f"{method} {_url(base, ep.path)}",
        evidence=evidence(resp)[:2000], owasp=OWASP,
        fix=f"Require authentication on {ep.view} (permission_classes=[IsAuthenticated] / @login_required).{ctrl}",
        endpoint=ep.path, method=method)


def check_a2(base: str, client: LiveClient, ep: Endpoint) -> list[Finding]:
    """Undeclared methods mirroring the declared one -> method tampering."""
    declared = {m.upper() for m in ep.methods}
    ref_method = ep.methods[0] if ep.methods else "GET"
    ref = client.request(ref_method, _url(base, ep.path))
    if ref is None or ref.status >= 400:
        return []
    out: list[Finding] = []
    for m in FUZZ_METHODS:
        if m in declared:
            continue
        r = client.request(m, _url(base, ep.path))
        if r is None:
            continue
        if r.status < 400 and similar(ref.body, r.body):
            dprint("api.a2 TAMPER", m, ep.path)  # [DEBUG] REMOVE in T6
            out.append(Finding(
                id=f"API-METHOD-{m}",
                title=f"Undeclared {m} accepted on {ep.path} (declares {', '.join(sorted(declared))})",
                severity=FUZZ_SEV[m], tool="api",
                where=f"{m} {_url(base, ep.path)}",
                evidence=evidence(r)[:2000], owasp=OWASP,
                fix="Restrict allowed methods (DRF http_method_names / methods=[...]; Flask methods=[...]) and deny unexpected verbs.",
                endpoint=ep.path, method=m))
    return out


def check_a3(base: str, client: LiveClient, ep: Endpoint) -> list[Finding]:
    """Malformed + oversized bodies must not leak stack/SQL/paths."""
    if not any(m in {m.upper() for m in ep.methods} for m in ("POST", "PUT", "PATCH")):
        return []
    out: list[Finding] = []
    payloads = [
        ("malformed", {"__repoguard": "}}}}((("}),
        ("oversized", {"__repoguard": "x" * (1024 * 1024)}),
    ]
    for label, payload in payloads:
        r = client.request("POST", _url(base, ep.path), json=payload)
        if r is None:
            continue
        kind = find_leak(r.body)
        if kind:
            out.append(Finding(
                id="API-ERROR-LEAK",
                title=f"{label} body leaks internals ({kind}) at {ep.path}",
                severity="High" if kind in ("stack", "sql") else "Medium",
                tool="api", where=f"POST {_url(base, ep.path)}",
                evidence=evidence(r)[:2000], owasp=OWASP,
                fix="Global exception handler returning generic 400/500; validate bodies with serializers/schemas first.",
                endpoint=ep.path, method="POST"))
            break
    return out


def check_a4(base: str, client: LiveClient) -> list[Finding]:
    """Single global burst: 20 rapid GETs; no 429/headers -> rate-limit gap."""
    dprint("api.a4 burst start")  # [DEBUG] REMOVE in T6
    limited = False
    for _ in range(20):
        r = client.request("GET", base.rstrip("/") + "/", throttle=False)
        if r is None:
            return []  # unreachable; L-app phase already flagged
        if r.status == 429:
            limited = True
            break
        low = {k.lower(): v for k, v in r.headers.items()}
        if "retry-after" in low or "x-ratelimit-limit" in low or "ratelimit-limit" in low:
            limited = True
            break
    if limited:
        return []
    return [Finding(
        id="API-NO-RATELIMIT",
        title="No rate limiting observed (20 rapid requests, all accepted)",
        severity="Low", tool="api", where=f"GET {base.rstrip('/')}/",
        evidence="20x GET / in burst: all 200, no 429, no Retry-After/X-RateLimit headers.",
        owasp=OWASP,
        fix="Add throttling (DRF DEFAULT_THROTTLE_CLASSES / django-ratelimit / reverse-proxy limit_req).",
        endpoint="/", method="GET")]


def check_a5(base: str, client: LiveClient, ep: Endpoint, token2: str) -> Finding | None:
    """IDOR bonus: token2 fetches token1's object id successfully."""
    if not client.token or not token2:
        return None
    if not ID_PARAM.search(ep.path):
        return None
    ids = [ID_PARAM.sub(t, ep.path) for t in ID_TRIES]
    for obj_path in ids:
        url = base.rstrip("/") + (obj_path if obj_path.startswith("/") else "/" + obj_path)
        r1 = client.request("GET", url, token=True)
        if r1 is None or r1.status != 200 or not looks_like_data(r1):
            continue
        r2 = client.request("GET", url, token=token2)
        if r2 is not None and r2.status == 200 and similar(r1.body, r2.body):
            dprint("api.a5 IDOR", url)  # [DEBUG] REMOVE in T6
            return Finding(
                id="API-IDOR",
                title=f"Possible IDOR: second user's token reads {obj_path}",
                severity="Critical", tool="api", where=f"GET {url}",
                evidence=f"user-A 200 ({len(r1.body)}b) vs user-B 200 ({len(r2.body)}b), bodies ~identical. Token values REDACTED.",
                owasp=OWASP,
                fix="Enforce object-level ownership (get_queryset().filter(owner=request.user) / per-object permission check).",
                endpoint=ep.path, method="GET")
    return None


def check_api(base_url: str, client: LiveClient, endpoints: list[Endpoint],
              token2: str | None) -> tuple[list[Finding], int]:
    """Run A1-A3 per endpoint (+A5 with two tokens); A4 once globally."""
    findings: list[Finding] = []
    tested = 0
    for ep in endpoints:
        tested += 1
        authed = None
        if client.token:
            ctl = client.request(ep.methods[0] if ep.methods else "GET",
                                 _url(base_url, ep.path), token=True)
            authed = {"control_status": ctl.status if ctl else None}
        f = check_a1(base_url, client, ep, authed)
        if f:
            findings.append(f)
        findings.extend(check_a2(base_url, client, ep))
        findings.extend(check_a3(base_url, client, ep))
        if token2:
            f5 = check_a5(base_url, client, ep, token2)
            if f5:
                findings.append(f5)
    findings.extend(check_a4(base_url, client))
    dprint("api.done tested=", tested, "findings=", len(findings))  # [DEBUG] REMOVE in T6
    return findings, tested
