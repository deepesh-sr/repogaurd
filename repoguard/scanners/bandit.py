"""S2a: bandit adapter. AST SAST: injection, exec, deser, crypto, traversal."""
from __future__ import annotations

import json
from pathlib import Path

from repoguard.models import Finding
from repoguard.scanners.base import ScannerAdapter
from repoguard.utils import subprocess as proc
from repoguard.utils.debug import dprint
from repoguard.utils.files import SKIP_DIRS
from repoguard.utils.owasp import bandit_owasp


class BanditAdapter(ScannerAdapter):
    name = "bandit"

    @property
    def binary(self) -> str:
        return "bandit"

    def run(self, target: Path) -> tuple[list[Finding], str]:
        dprint("bandit.start", str(target))  # [DEBUG] REMOVE in T6
        if not self.is_available():
            return self._unavailable("binary not installed")
        try:
            skips = ",".join(f"./{d}" for d in sorted(SKIP_DIRS))
            res = proc.run(["bandit", "-r", str(target), "-f", "json", "-q",
                            "--exclude", skips], cwd=target)
            if res.missing:
                return self._unavailable("binary not installed")
            if res.timed_out:
                return [], "error (timeout)"
            try:
                data = json.loads(res.stdout or "{}")
            except json.JSONDecodeError:
                return [], f"error (unparseable output, rc={res.returncode})"
            findings = self.parse(data)
            dprint("bandit.done findings=", len(findings))  # [DEBUG] REMOVE in T6
            return findings, f"ok ({len(findings)} findings)"
        except Exception as e:  # never raise
            return [], f"error ({e})"

    def parse(self, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        for item in data.get("results", []) or []:
            test_id = str(item.get("test_id", "?"))
            sev_raw = str(item.get("issue_severity", "Medium")).capitalize()
            severity = sev_raw if sev_raw in ("Critical", "High", "Medium", "Low") else "Medium"
            if severity == "Low" and test_id in ("B404", "B603", "B607"):
                continue  # import-only / partial-path noise; real sinks still reported
            fname = str(item.get("filename", "?"))
            lineno = item.get("line_number")
            findings.append(Finding(
                id=f"BANDIT-{test_id}",
                title=f"{item.get('test_name', test_id)} [{test_id}]",
                severity=severity,
                tool="bandit",
                where=f"{fname}:{lineno}",
                evidence=str(item.get("code", "") or item.get("issue_text", ""))[:2000],
                owasp=bandit_owasp(test_id),
                fix=self._fix_hint(test_id),
                file=fname,
                line=lineno if isinstance(lineno, int) else None,
            ))
        return findings

    @staticmethod
    def _fix_hint(test_id: str) -> str:
        hints = {
            "B301": "Avoid pickle on untrusted data; use json with strict schema validation.",
            "B302": "Do not use marshal for untrusted data; use json.",
            "B303": "Replace md5/sha1 with sha256+ (hashlib) or bcrypt/argon2 for passwords.",
            "B307": "Remove eval(); use ast.literal_eval or a safe parser.",
            "B602": "Drop shell=True; pass argv list with shell=False and shlex-quote inputs.",
            "B603": "Validate executable path (absolute, allowlisted) before subprocess call.",
            "B607": "Use absolute executable path, not a partial path.",
            "B608": "Parameterize SQL (placeholders); never format values into the query string.",
            "B501": "Use requests with verify=True (default); pin CA bundle if needed.",
            "B506": "Use yaml.safe_load, never yaml.load without Loader=SafeLoader.",
            "B105": "Move secret to env var; fail closed if unset.",
        }
        return hints.get(test_id.upper(), "Review flagged construct against bandit docs; apply safe alternative and re-scan.")
