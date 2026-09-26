"""S1: pip-audit adapter. Known CVEs + severity + fixed version."""
from __future__ import annotations

import json
from pathlib import Path

from repoguard.models import Finding
from repoguard.scanners.base import ScannerAdapter
from repoguard.utils import subprocess as proc
from repoguard.utils.debug import dprint
from repoguard.utils.owasp import TOOL_DEFAULT_OWASP, cvss_to_severity


class PipAuditAdapter(ScannerAdapter):
    name = "pip-audit"

    @property
    def binary(self) -> str:
        return "pip-audit"

    def _manifests(self, target: Path) -> tuple[list[Path], bool]:
        reqs = sorted(target.glob("requirements*.txt"))
        locked = (target / "poetry.lock").exists() or (target / "Pipfile.lock").exists()
        return reqs, locked

    def run(self, target: Path) -> tuple[list[Finding], str]:
        dprint("pip_audit.start", str(target))  # [DEBUG] REMOVE in T6
        if not self.is_available():
            return self._unavailable("binary not installed")
        try:
            reqs, locked = self._manifests(target)
            if not reqs and not locked:
                return [], "skipped (no requirements*.txt / poetry.lock / Pipfile.lock)"
            cmd = ["pip-audit", "-f", "json"]
            for r in reqs:
                cmd += ["-r", str(r)]
            if locked:
                cmd.append("--locked")
            res = proc.run(cmd, cwd=target)
            if res.missing:
                return self._unavailable("binary not installed")
            if res.timed_out:
                return [], "error (timeout)"
            try:
                data = json.loads(res.stdout or "[]")
            except json.JSONDecodeError:
                return [], f"error (unparseable output, rc={res.returncode})"
            findings = self.parse(data, reqs)
            dprint("pip_audit.done findings=", len(findings))  # [DEBUG] REMOVE in T6
            # pip-audit rc: 0 = clean, 1 = vulns found OR resolution failure.
            # Zero parsed findings + failure markers on stderr = failed audit,
            # not a clean bill of health.
            if not findings and ("failed" in (res.stderr or "").lower()
                                 or res.returncode not in (0, 1)):
                err = (res.stderr or "").strip().splitlines()
                hint = err[-1][:200] if err else f"rc={res.returncode}"
                return [], f"error (audit failed: {hint})"
            return findings, f"ok ({len(findings)} findings)"
        except Exception as e:  # never raise
            return [], f"error ({e})"

    def parse(self, data, reqs: list[Path]) -> list[Finding]:
        where = str(reqs[0]) if reqs else "poetry.lock/Pipfile.lock"
        findings: list[Finding] = []
        deps = data if isinstance(data, list) else data.get("dependencies", data)
        if not isinstance(deps, list):
            return []
        for dep in deps:
            if not isinstance(dep, dict):
                continue
            pkg = dep.get("name", "?")
            ver = dep.get("version", "?")
            for vuln in dep.get("vulns", []) or []:
                vid = vuln.get("id") or (vuln.get("aliases") or ["?"])[0]
                spec = vuln.get("spec", "")
                fixed = ", ".join(vuln.get("fix_versions", []) or []) or "no fixed version published"
                score = None
                for s in vuln.get("severity", []) or []:
                    try:
                        score = float(s.get("score", 0))
                        break
                    except (TypeError, ValueError):
                        continue
                severity = cvss_to_severity(score)
                findings.append(Finding(
                    id=f"PIP-AUDIT-{vid}",
                    title=f"{pkg} {ver}: {vid} (spec {spec})",
                    severity=severity,
                    tool="pip-audit",
                    where=where,
                    evidence=f"{pkg}=={ver} vulnerable to {vid} {spec}; fix: {fixed}".strip()[:2000],
                    owasp=TOOL_DEFAULT_OWASP["pip-audit"],
                    fix=f"pip install '{pkg}=={fixed}'" if fixed != "no fixed version published"
                         else f"Upgrade or replace {pkg}; no fixed version published for {vid}.",
                    references=[f"https://osv.dev/vulnerability/{vid}"],
                ))
        return findings
