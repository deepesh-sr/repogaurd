"""T4 tests: fix-first ranking + report render (PLAN report contract)."""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoguard.models import Finding, Report, build_summary  # noqa: E402
from repoguard.ranking import TOP_N, rank, top  # noqa: E402
from repoguard.report.html_writer import write_html  # noqa: E402



def _mk(fid, sev, tool="bandit", fix="fix it"):
    return Finding(id=fid, title=f"t-{fid}", severity=sev, tool=tool,
                   where="f.py:1", evidence="e", owasp="A03", fix=fix,
                   file="f.py", line=1)


def test_critical_unauth_outranks_50_lows():
    findings = [_mk(f"B-{i}", "Low") for i in range(50)]
    findings.append(_mk("API-UNAUTH-EXPOSURE", "Critical", tool="api"))
    ranked = rank(findings)
    assert ranked[0].id == "API-UNAUTH-EXPOSURE"


def test_boost_order_within_severity():
    findings = [_mk("BANDIT-B301", "High"),
                _mk("GITLEAKS-generic-api-key", "High"),
                _mk("CFG-03", "High", tool="config")]
    assert [f.id for f in rank(findings)] == [
        "GITLEAKS-generic-api-key", "CFG-03", "BANDIT-B301"]


def test_pip_audit_boost_only_with_fix():
    with_fix = _mk("PIP-AUDIT-CVE-1", "High", tool="pip-audit", fix="pip install 'x==1.2'")
    no_fix = _mk("PIP-AUDIT-CVE-2", "High", tool="pip-audit",
                 fix="Upgrade x; no fixed version published for CVE-2.")
    plain = _mk("BANDIT-B602", "High")
    assert [f.id for f in rank([plain, no_fix, with_fix])] == [
        "PIP-AUDIT-CVE-1", "PIP-AUDIT-CVE-2", "BANDIT-B602"]  # fix-boost, then tool order


def test_top12_and_determinism():
    findings = [_mk(f"B-{i:03d}", "Low") for i in range(400)]
    findings.append(_mk("API-IDOR", "Critical", tool="api"))
    assert top(findings)[0].id == "API-IDOR"
    assert len(top(findings)) == TOP_N == 12
    assert [f.id for f in rank(findings)] == [f.id for f in rank(list(reversed(findings)))]


def test_html_fix_first_panel_and_offline(tmp_path):
    crit = _mk("API-UNAUTH-EXPOSURE", "Critical", tool="api")
    lows = [_mk(f"B-{i}", "Low") for i in range(3)]
    rep = Report(target="t", base_url=None, generated_at="now",
                 summary=build_summary([crit] + lows), findings=rank([crit] + lows),
                 endpoints=[], scanner_status={})
    dest = tmp_path / "report.html"
    write_html(rep, dest)
    page = dest.read_text()
    assert "Fix first" in page and "API-UNAUTH-EXPOSURE" in page
    assert page.index("Fix first") < page.index("B-0")  # panel precedes detail
    assert "<details open>" in page and "<details>" in page
    assert not re.search(r'<link[^>]+http|<script[^>]+src="http', page)


def test_summary_fix_first_key(tmp_path):
    from repoguard.runner import run_scan
    from repoguard.cli import build_parser
    import json
    p = build_parser()
    ns = p.parse_args(["scan", "tests/fixtures/empty_repo", "--output", str(tmp_path)])
    assert run_scan(ns) == 0
    data = json.loads((tmp_path / "findings.json").read_text())
    assert data["summary"]["fix_first"] == []
