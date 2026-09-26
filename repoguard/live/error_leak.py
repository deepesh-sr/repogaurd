"""L4: stack traces / Django debug page on errors (signatures in http.py)."""
from __future__ import annotations

from repoguard.live.http import LiveClient, evidence, find_leak
from repoguard.models import Finding
from repoguard.utils.debug import dprint
from repoguard.utils.owasp import TOOL_DEFAULT_OWASP

OWASP = TOOL_DEFAULT_OWASP["live"]

TRIGGERS = [
    "/repoguard-nonexistent-xyz",
    "/repoguard-nonexistent-xyz?q={{7*7}}",
]


def check(base_url: str, client: LiveClient) -> list[Finding]:
    dprint("errorleak.start", base_url)  # [DEBUG] REMOVE in T6
    findings: list[Finding] = []
    base = base_url.rstrip("/")
    for t in TRIGGERS:
        resp = client.request("GET", base + t)
        if resp is None or resp.status < 400 and resp.status != 200:
            continue
        kind = find_leak(resp.body)
        if kind:
            severity = "High" if kind in ("stack", "sql") else "Medium"
            findings.append(Finding(
                id="LIVE-ERROR-LEAK",
                title=f"Error page leaks internals ({kind}) at {t}", severity=severity,
                tool="live", where=f"GET {base + t}", evidence=evidence(resp)[:2000],
                owasp=OWASP,
                fix="DEBUG=False; custom 404/500 handlers returning generic pages; log tracebacks server-side only.",
                endpoint=t, method="GET"))
            break  # one finding suffices; the leak class is proven
    dprint("errorleak.done findings=", len(findings))  # [DEBUG] REMOVE in T6
    return findings
