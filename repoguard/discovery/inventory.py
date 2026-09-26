"""Merge Django + Flask discovery -> Endpoint list + DISC-* findings.

One finding per endpoint max: open (High) beats allowany-default (Medium).
"""
from __future__ import annotations

from pathlib import Path

from repoguard.discovery.django_parser import RawEndpoint, discover_django
from repoguard.discovery.flask_parser import discover_flask
from repoguard.discovery.permissions import classify, parse_drf_default
from repoguard.models import Endpoint, Finding
from repoguard.utils.debug import dprint
from repoguard.utils.owasp import TOOL_DEFAULT_OWASP

OWASP = TOOL_DEFAULT_OWASP["discovery"]


def _finding_for(ep: Endpoint) -> Finding | None:
    if ep.protection == "open":
        return Finding(
            id="DISC-OPEN-ENDPOINT",
            title=f"Endpoint with no authentication: {', '.join(ep.methods)} {ep.path}",
            severity="High",
            tool="discovery",
            where=f"{ep.file}:{ep.line}",
            evidence=f"{', '.join(ep.methods)} {ep.path} -> {ep.view} (no auth/permission classes, no @login_required).",
            owasp=OWASP,
            fix="Add permission_classes=[IsAuthenticated] (DRF) or @login_required (Django/Flask).",
            file=ep.file, line=ep.line, endpoint=ep.path,
            method=",".join(ep.methods),
        )
    if ep.protection == "allowany-default":
        return Finding(
            id="DISC-ALLOWANY-DEFAULT",
            title=f"Endpoint on permissive global default: {', '.join(ep.methods)} {ep.path}",
            severity="Medium",
            tool="discovery",
            where=f"{ep.file}:{ep.line}",
            evidence=f"{', '.join(ep.methods)} {ep.path} -> {ep.view} inherits global AllowAny default.",
            owasp=OWASP,
            fix="Set REST_FRAMEWORK DEFAULT_PERMISSION_CLASSES to IsAuthenticated and opt out per-view with AllowAny only where intended.",
            file=ep.file, line=ep.line, endpoint=ep.path,
            method=",".join(ep.methods),
        )
    return None


def discover(target: Path) -> tuple[list[Endpoint], list[Finding]]:
    target = Path(target)
    if not target.exists():
        return [], []
    default = parse_drf_default(target)
    dprint("inventory.drf_default", default)  # [DEBUG] REMOVE in T6
    raw: list[RawEndpoint] = discover_django(target) + discover_flask(target)

    merged: dict[tuple[str, str], RawEndpoint] = {}
    for r in raw:
        for m in r.methods:
            key = (r.path, m)
            if key not in merged:
                merged[key] = RawEndpoint(path=r.path, methods=[m], view=r.view,
                                          file=r.file, line=r.line, auth=list(r.auth),
                                          permissions=list(r.permissions), source=r.source,
                                          is_class=r.is_class)

    endpoints: list[Endpoint] = []
    findings: list[Finding] = []
    for (path, method), r in sorted(merged.items()):
        protection = classify(r.auth, r.permissions, default, r.is_class)
        ep = Endpoint(path=path, methods=[method], view=r.view, file=r.file,
                      line=r.line, auth=r.auth, permissions=r.permissions,
                      protection=protection, source=r.source)
        dprint("inventory.endpoint", method, path, protection)  # [DEBUG] REMOVE in T6
        endpoints.append(ep)
        f = _finding_for(ep)
        if f is not None:
            findings.append(f)
    dprint("inventory.done endpoints=", len(endpoints), "findings=", len(findings))  # [DEBUG] REMOVE in T6
    return endpoints, findings
