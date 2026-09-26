"""S5: repo hygiene. Committed .env / keys / certs / DB dumps (S5).

Filename globs + content sniffing from rules/hygiene_patterns.json.
Fires on presence in the tree even with no recognizable secret string
(that is gitleaks' job). Scans working tree; git-aware-ness is out of v1.
"""
from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

from repoguard.models import Finding
from repoguard.scanners.base import ScannerAdapter
from repoguard.utils.debug import dprint
from repoguard.utils.files import iter_files
from repoguard.utils.owasp import TOOL_DEFAULT_OWASP

OWASP = TOOL_DEFAULT_OWASP["hygiene"]
RULES_FILE = Path(__file__).parent.parent / "rules" / "hygiene_patterns.json"


def load_rules() -> dict:
    return json.loads(RULES_FILE.read_text(encoding="utf-8"))


def scan_tree(target: Path, rules: dict | None = None) -> list[Finding]:
    rules = rules or load_rules()
    globs = rules.get("filename_globs", [])
    sniffs = [(r["pattern"], r["kind"], r.get("severity", "Medium"))
              for r in rules.get("content_sniffs", [])]
    compiled = [(re.compile(p), k, s) for p, k, s in sniffs]
    findings: list[Finding] = []
    for f in iter_files(target):
        name = f.name
        hit = next((g for g in globs if fnmatch.fnmatch(name, g["glob"])), None)
        sniff_kind = sniff_sev = None
        if hit is None and f.stat().st_size < 5_000_000:
            try:
                head = f.read_text(encoding="utf-8", errors="replace")[:20000]
            except OSError:
                continue
            for rx, kind, sev in compiled:
                if rx.search(head):
                    sniff_kind, sniff_sev = kind, sev
                    break
            if sniff_kind is None:
                continue
        elif hit is None:
            continue
        kind = sniff_kind or hit["kind"]
        severity = sniff_sev or hit.get("severity", "Medium")
        rel = str(f.relative_to(target))
        dprint("hygiene.flag", rel, kind)  # [DEBUG] REMOVE in T6
        findings.append(Finding(
            id=f"HYG-{kind.upper().replace('-', '_')}-COMMITTED",
            title=f"Committed {kind} file: {rel}",
            severity=severity,
            tool="hygiene",
            where=rel,
            evidence=f"File {rel} matches hygiene rule ({kind}); contents not shown.",
            owasp=OWASP,
            fix=("git rm --cached " + rel + "; add to .gitignore; rotate any credential it held; "
                 "purge from history with git-filter-repo if already pushed."),
            file=rel,
        ))
    return findings


class HygieneAdapter(ScannerAdapter):
    name = "hygiene"

    @property
    def binary(self) -> str:
        return "builtin"

    def is_available(self) -> bool:
        return True

    def run(self, target: Path) -> tuple[list[Finding], str]:
        dprint("hygiene.start", str(target))  # [DEBUG] REMOVE in T6
        if not Path(target).exists():
            return [], f"error (target not found: {target})"
        try:
            findings = scan_tree(target)
            dprint("hygiene.done findings=", len(findings))  # [DEBUG] REMOVE in T6
            return findings, f"ok ({len(findings)} findings)"
        except Exception as e:  # never raise
            return [], f"error ({e})"
