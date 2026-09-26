"""Fix-first ranking: exploitability now beats CVSS alone.

Sort key (lower = fix first): (severity_rank, boost, tool_order, file, line).
Boosts match on finding-ID prefixes so future rules inherit them.
"""
from __future__ import annotations

from repoguard.models import SEVERITY_ORDER, Finding
from repoguard.utils.debug import dprint

TOP_N = 12

# (id prefix, boost). Negative floats the finding up.
BOOSTS: tuple[tuple[str, int], ...] = (
    ("API-UNAUTH-EXPOSURE", -100),
    ("API-IDOR", -100),
    ("GITLEAKS-", -50),
    ("HYG-PRIVATE_KEY-COMMITTED", -50),
    ("HYG-ENV-COMMITTED", -50),
    ("CFG-01", -30),  # DEBUG=True
    ("CFG-03", -30),  # hardcoded SECRET_KEY
    ("CFG-04", -30),  # hardcoded DB password
    ("CFG-07", -30),  # CORS all origins
    ("DISC-OPEN-ENDPOINT", -30),
    ("PIP-AUDIT-", -10),  # only when a fixed version exists (see _boost)
)

TOOL_ORDER = {"api": 0, "gitleaks": 1, "config": 2, "discovery": 3,
              "pip-audit": 4, "bandit": 5, "semgrep": 6, "hygiene": 7,
              "live": 8}


def _boost(f: Finding) -> int:
    for prefix, b in BOOSTS:
        if f.id.startswith(prefix):
            if prefix == "PIP-AUDIT-" and "no fixed version" in f.fix:
                continue  # no actionable fix: no boost
            return b
    return 0


def _key(f: Finding) -> tuple:
    return (SEVERITY_ORDER.get(f.severity, 99), _boost(f),
            TOOL_ORDER.get(f.tool, 99), f.file or "", f.line or 0, f.id)


def rank(findings: list[Finding]) -> list[Finding]:
    """Stable sorted copy, fix-first order."""
    dprint("ranking.rank n=", len(findings))  # [DEBUG] REMOVE in T6
    return sorted(findings, key=_key)


def top(findings: list[Finding], n: int = TOP_N) -> list[Finding]:
    return rank(findings)[:n]
