"""S2b: semgrep adapter. Pattern SAST over p/python,p/django,p/flask."""
from __future__ import annotations

import json
from pathlib import Path

from repoguard.models import Finding
from repoguard.scanners.base import ScannerAdapter
from repoguard.utils import subprocess as proc
from repoguard.utils.debug import dprint
from repoguard.utils.owasp import semgrep_owasp

MAX_FINDINGS = 200


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"

    @property
    def binary(self) -> str:
        return "semgrep"

    def run(self, target: Path) -> tuple[list[Finding], str]:
        dprint("semgrep.start", str(target))  # [DEBUG] REMOVE in T6
        if not self.is_available():
            return self._unavailable("binary not installed")
        try:
            res = proc.run(["semgrep", "--config", "p/python", "--config", "p/django",
                            "--config", "p/flask", "--json", "--quiet", str(target)],
                           cwd=target, timeout=300)
            if res.missing:
                return self._unavailable("binary not installed")
            if res.timed_out:
                return [], "error (timeout)"
            try:
                data = json.loads(res.stdout or "{}")
            except json.JSONDecodeError:
                return [], f"error (unparseable output, rc={res.returncode})"
            findings, truncated = self.parse(data, MAX_FINDINGS)
            status = f"ok ({len(findings)} findings)"
            if truncated:
                findings.append(self._truncation_note(truncated))
                status += f" (+{truncated} truncated)"
            dprint("semgrep.done findings=", len(findings))  # [DEBUG] REMOVE in T6
            return findings, status
        except Exception as e:  # never raise
            return [], f"error ({e})"

    def parse(self, data: dict, cap: int = MAX_FINDINGS) -> tuple[list[Finding], int]:
        results = data.get("results", []) or []
        findings: list[Finding] = []
        for r in results[:cap]:
            extra = r.get("extra", {}) or {}
            meta = extra.get("metadata", {}) or {}
            sev_raw = str(extra.get("severity", "WARNING")).upper()
            severity = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}.get(sev_raw, "Medium")
            path = str(r.get("path", "?"))
            line = (r.get("start") or {}).get("line")
            check = str(r.get("check_id", "?"))
            findings.append(Finding(
                id=f"SEMGREP-{check.split('.')[-1]}",
                title=check,
                severity=severity,
                tool="semgrep",
                where=f"{path}:{line}",
                evidence=str(extra.get("message", "") or extra.get("lines", ""))[:2000],
                owasp=semgrep_owasp(meta),
                fix="Apply the rule's recommended sink fix (parameterize/escape/allowlist) and re-scan.",
                file=path,
                line=line if isinstance(line, int) else None,
                references=[meta["references"]] if isinstance(meta.get("references"), str) else [],
            ))
        return findings, max(0, len(results) - cap)

    @staticmethod
    def _truncation_note(n: int) -> Finding:
        from repoguard.utils.owasp import TOOL_DEFAULT_OWASP
        return Finding(
            id="SEMGREP-TRUNCATED",
            title=f"Semgrep output truncated: {n} further matches capped (see fix-first policy)",
            severity="Info",
            tool="semgrep",
            where=".",
            evidence=f"{n} semgrep matches beyond the {MAX_FINDINGS} cap are omitted from detail; counts preserved.",
            owasp=TOOL_DEFAULT_OWASP["semgrep"],
            fix="Triage the top findings first; raise the cap only for audit completeness.",
        )
