"""L3: exposed paths + version disclosure (frozen probe list)."""
from __future__ import annotations

from repoguard.live.http import LiveClient, evidence
from repoguard.models import Finding
from repoguard.utils.owasp import TOOL_DEFAULT_OWASP

OWASP = TOOL_DEFAULT_OWASP["live"]

# (path, severity_if_exposed, signature_substrings, title)
PROBES = [
    ("/admin", "Medium", ["django administration", "log in", "admin"], "Exposed /admin panel"),
    ("/admin/", "Medium", ["django administration", "log in", "admin"], "Exposed /admin/ panel"),
    ("/.env", "High", ["=", "key", "secret", "password"], "Exposed /.env file"),
    ("/.git/HEAD", "High", ["ref:"], "Exposed /.git metadata"),
    ("/debug", "Medium", ["debug", "traceback", "toolbar"], "Exposed /debug page"),
    ("/console", "Medium", ["console", "debugger", "pin"], "Exposed /console debugger"),
    ("/server-status", "Medium", ["apache status", "server-status"], "Exposed /server-status"),
    ("/static/", "Low", ["index of /", "parent directory"], "Directory listing under /static/"),
    ("/media/", "Low", ["index of /", "parent directory"], "Directory listing under /media/"),
]

VERSION_HEADERS = ("server", "x-powered-by", "x-framework", "x-version")


def check(base_url: str, client: LiveClient) -> list[Finding]:
    findings: list[Finding] = []
    base = base_url.rstrip("/")
    root = client.request("GET", base + "/")
    headers = dict(root.headers) if root else {}
    for vh in VERSION_HEADERS:
        for k, v in headers.items():
            if k.lower() == vh and v.strip() and v.strip() != "None":
                findings.append(Finding(
                    id="LIVE-VERSION", title=f"Server/framework version disclosed ({k}: {v[:80]})",
                    severity="Low", tool="live", where=f"GET {base}/",
                    evidence=f"{k}: {v[:200]}", owasp=OWASP,
                    fix="Suppress version banners (e.g. server_tokens off; remove X-Powered-By).",
                    endpoint="/", method="GET"))
                break
    for path, severity, sigs, title in PROBES:
        resp = client.request("GET", base + path)
        if resp is None or resp.status != 200 or len(resp.body.strip()) < 20:
            continue
        low = resp.body.lower()
        if any(s in low for s in sigs):
            findings.append(Finding(
                id=f"LIVE-EXPOSED-{path.strip('/').upper().replace('/', '_').replace('.', '_') or 'ROOT'}",
                title=title, severity=severity, tool="live",
                where=f"GET {base + path}", evidence=evidence(resp)[:2000],
                owasp=OWASP,
                fix=f"Block {path} at the web server / WSGI layer; require auth; never deploy .env/.git.",
                endpoint=path, method="GET"))
    return findings
