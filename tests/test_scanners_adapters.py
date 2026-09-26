"""T1a tests: pip-audit/bandit/semgrep/gitleaks adapters (PLAN S1-S3).

Unit tests use canned scanner JSON (no binaries needed). Integration
tests run live binaries when present, else skip.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoguard.scanners.bandit import BanditAdapter  # noqa: E402
from repoguard.scanners.gitleaks import GitleaksAdapter  # noqa: E402
from repoguard.scanners.pip_audit import PipAuditAdapter  # noqa: E402
from repoguard.scanners.semgrep import SemgrepAdapter  # noqa: E402
from repoguard.utils.owasp import bandit_owasp, cvss_to_severity, semgrep_owasp  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
VULN = FIXTURES / "vuln_repo"

print("[DEBUG:test] T1a module loaded")  # [DEBUG] println -- REMOVE in T6


# --- owasp helpers ---

def test_cvss_bands_locked():
    assert cvss_to_severity(9.8) == "Critical"
    assert cvss_to_severity(7.5) == "High"
    assert cvss_to_severity(5.0) == "Medium"
    assert cvss_to_severity(2.0) == "Low"
    assert cvss_to_severity(None) == "High"


def test_bandit_owasp_known_and_fallback():
    assert "A08" in bandit_owasp("B301")
    assert "A03" in bandit_owasp("B602")
    assert bandit_owasp("B999") != ""


def test_semgrep_owasp_metadata_and_cwe():
    assert semgrep_owasp({"owasp": "A01:2021 — x"}) == "A01:2021 — x"
    assert "A07" in semgrep_owasp({"cwe": "CWE-798: hardcoded creds"})
    assert semgrep_owasp({}) != ""


# --- pip-audit ---

CANNED_PIP = [{
    "name": "django", "version": "3.2.0",
    "vulns": [{
        "id": "GHSA-2hrw-hx67-34x6", "spec": ">=3.2,<3.2.25",
        "fix_versions": ["3.2.25"], "aliases": ["CVE-2024-39329"],
        "severity": [{"spec": "CVSS_V3", "score": 7.5}],
    }],
}]


def test_pip_audit_parse_canned():
    findings = PipAuditAdapter().parse(CANNED_PIP, [Path("requirements-vuln.txt")])
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "PIP-AUDIT-GHSA-2hrw-hx67-34x6"
    assert f.severity == "High"
    assert "3.2.25" in f.fix
    assert "A06" in f.owasp
    assert f.tool == "pip-audit"


def test_pip_audit_resolution_failure_is_error_not_clean(monkeypatch, tmp_path):
    from repoguard.scanners import pip_audit as pa
    from repoguard.utils.subprocess import ProcResult
    (tmp_path / "requirements.txt").write_text("django==4.2\n")
    def fake_run(cmd, cwd=None, timeout=300):
        return ProcResult(returncode=1, stdout="", stderr="ERROR: Failed to install packages",
                          timed_out=False, missing=False)
    monkeypatch.setattr(pa.proc, "run", fake_run)
    monkeypatch.setattr(PipAuditAdapter, "is_available", lambda self: True)
    findings, status = PipAuditAdapter().run(tmp_path)
    print("[DEBUG:test] pip-audit failure status=", status)  # [DEBUG] println -- REMOVE in T6
    assert findings == [] and status.startswith("error")


def test_pip_audit_no_manifest(tmp_path):
    findings, status = PipAuditAdapter().run(tmp_path)
    assert findings == [] and "skipped" in status


@pytest.mark.skipif(shutil.which("pip-audit") is None, reason="pip-audit not installed")
def test_pip_audit_live_on_fixture():
    findings, status = PipAuditAdapter().run(VULN)
    assert status.startswith("ok"), status
    assert len(findings) >= 1, "expected CVEs for django==3.2.0 / urllib3==1.26.5"


# --- bandit ---

CANNED_BANDIT = {"results": [{
    "filename": "vuln_code.py", "test_name": "pickle_deserialization",
    "test_id": "B301", "issue_severity": "Medium",
    "issue_text": "Pickle and modules that wrap it can be unsafe.",
    "line_number": 12, "code": "11  return pickle.loads(blob)",
}]}


def test_bandit_parse_canned():
    findings = BanditAdapter().parse(CANNED_BANDIT)
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "BANDIT-B301" and f.where == "vuln_code.py:12"
    assert "A08" in f.owasp and f.line == 12


@pytest.mark.skipif(shutil.which("bandit") is None, reason="bandit not installed")
def test_bandit_live_on_fixture():
    findings, status = BanditAdapter().run(VULN)
    assert status.startswith("ok"), status
    ids = {f.id for f in findings}
    assert "BANDIT-B301" in ids and "BANDIT-B602" in ids


# --- semgrep ---

CANNED_SEMGREP = {"results": [{
    "check_id": "python.lang.security.audit.eval-detected",
    "path": "vuln_code.py", "start": {"line": 16},
    "extra": {"message": "eval detected", "severity": "ERROR",
              "metadata": {"cwe": "CWE-95: code injection"}, "lines": "return eval(code)"},
}]}


def test_semgrep_parse_canned():
    findings, truncated = SemgrepAdapter().parse(CANNED_SEMGREP)
    assert truncated == 0 and len(findings) == 1
    assert findings[0].severity == "High" and "A03" in findings[0].owasp


def test_semgrep_cap_and_truncation_note():
    big = {"results": [CANNED_SEMGREP["results"][0]] * 250}
    findings, truncated = SemgrepAdapter().parse(big, cap=200)
    assert truncated == 50 and len(findings) == 200


def test_semgrep_missing_binary_reports_status():
    if shutil.which("semgrep") is not None:
        pytest.skip("semgrep installed; missing-path covered by gitleaks test")
    findings, status = SemgrepAdapter().run(VULN)
    assert "missing" in status and findings == []


# --- gitleaks ---

CANNED_GIT = [{
    "RuleID": "generic-api-key", "File": "app/settings.py",
    "StartLine": 3, "Commit": "abc123def456", "Fingerprint": "fp1:2",
}]


def test_gitleaks_parse_canned_redacted():
    findings = GitleaksAdapter().parse(CANNED_GIT)
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "GITLEAKS-generic-api-key" and f.severity == "High"
    assert "Secret" not in f.evidence and "REDACTED" in f.evidence
    assert "A07" in f.owasp


def test_gitleaks_missing_binary_reports_status():
    if shutil.which("gitleaks") is not None:
        pytest.skip("gitleaks installed")
    findings, status = GitleaksAdapter().run(VULN)
    assert "missing" in status and findings == []


# --- runner wiring ---

def test_static_phase_merges_adapters_and_status():
    from repoguard.runner import _static_phase
    findings, status = _static_phase(VULN)
    assert set(status) == {"pip-audit", "bandit", "semgrep", "gitleaks", "config", "hygiene"}
    assert isinstance(findings, list)
