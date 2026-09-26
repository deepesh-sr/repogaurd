"""S3: gitleaks adapter. Secrets in code AND git history (always redacted)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from repoguard.models import Finding
from repoguard.scanners.base import ScannerAdapter
from repoguard.utils import subprocess as proc
from repoguard.utils.debug import dprint
from repoguard.utils.owasp import TOOL_DEFAULT_OWASP

CRITICAL_RULES = {"aws-access-token", "aws-secret-key", "github-pat", "private-key",
                  "generic-api-key-at-head"}


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"

    @property
    def binary(self) -> str:
        return "gitleaks"

    def run(self, target: Path) -> tuple[list[Finding], str]:
        dprint("gitleaks.start", str(target))  # [DEBUG] REMOVE in T6
        if not self.is_available():
            return self._unavailable("binary not installed")
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                report = tmp.name
            cmd = ["gitleaks", "detect", "--source", str(target),
                   "--report-format", "json", "--report-path", report,
                   "--redact", "--no-banner"]
            if not (target / ".git").exists():
                cmd.append("--no-git")
            res = proc.run(cmd, cwd=target)
            if res.missing:
                return self._unavailable("binary not installed")
            if res.timed_out:
                return [], "error (timeout)"
            try:
                raw = Path(report).read_text(encoding="utf-8") if Path(report).exists() else ""
                data = json.loads(raw or "[]")
            except json.JSONDecodeError:
                return [], f"error (unparseable output, rc={res.returncode})"
            finally:
                try:
                    Path(report).unlink(missing_ok=True)
                except OSError:
                    pass
            shallow = (target / ".git" / "shallow").exists()
            findings = self.parse(data if isinstance(data, list) else [])
            if shallow:
                findings.append(self._shallow_note())
            dprint("gitleaks.done findings=", len(findings))  # [DEBUG] REMOVE in T6
            status = f"ok ({len(findings)} findings)"
            if shallow:
                status += " [shallow clone: history incomplete]"
            return findings, status
        except Exception as e:  # never raise
            return [], f"error ({e})"

    def parse(self, leaks: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        for leak in leaks:
            if not isinstance(leak, dict):
                continue
            rule = str(leak.get("RuleID", "generic"))
            # REDACTION AUDIT: never persist Secret/Match values.
            assert "Secret" not in leak or leak.get("Secret") in (None, ""), "unredacted secret!"
            fpath = str(leak.get("File", "?"))
            line = leak.get("StartLine")
            commit = str(leak.get("Commit", "working tree"))
            at_head = commit in ("working tree", "", "HEAD")
            severity = "Critical" if (rule in CRITICAL_RULES and at_head) else "High"
            findings.append(Finding(
                id=f"GITLEAKS-{rule}",
                title=f"Possible secret: {rule} in {fpath}",
                severity=severity,
                tool="gitleaks",
                where=f"{fpath}:{line}" if isinstance(line, int) else fpath,
                evidence=f"Rule {rule} matched in {fpath} (commit {commit[:12]}); value REDACTED.".strip()[:2000],
                owasp=TOOL_DEFAULT_OWASP["gitleaks"],
                fix="Rotate the credential now; purge from history (git-filter-repo); move to env var/secret manager; add to .gitleaksignore only after rotation.",
                file=fpath,
                line=line if isinstance(line, int) else None,
            ))
        return findings

    @staticmethod
    def _shallow_note() -> Finding:
        return Finding(
            id="GITLEAKS-SHALLOW",
            title="Shallow git clone: history scan incomplete",
            severity="Info",
            tool="gitleaks",
            where=".git/shallow",
            evidence="Clone depth < full history; gitleaks covered the working tree + partial history only.",
            owasp=TOOL_DEFAULT_OWASP["gitleaks"],
            fix="Re-run on a full clone (git fetch --unshallow) for complete history coverage.",
        )
