"""T0 tests: CLI exit-code policy + report writers (PLAN CLI-6/CLI-7)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoguard.cli import build_parser, main  # noqa: E402
from repoguard.models import Finding, Report, build_summary  # noqa: E402
from repoguard.report.html_writer import write_html  # noqa: E402
from repoguard.report.json_writer import write_json  # noqa: E402
from repoguard.runner import run_scan  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def _args(path: Path, **kw):
    p = build_parser()
    base = {"path": str(path), "url": None, "token": None, "token2": None,
            "output": None, "fail_on": "critical", "timeout": 10, "verbose": False}
    base.update(kw)
    ns = argparse_Namespace(base)
    return ns


class argparse_Namespace:
    def __init__(self, d):
        self.__dict__.update(d)


def test_scan_empty_repo_exit_0_and_writes_reports(tmp_path):
    ns = _args(FIXTURES / "empty_repo", output=str(tmp_path / "out"))
    code = run_scan(ns)
    assert code == 0
    assert (tmp_path / "out" / "findings.json").exists()
    assert (tmp_path / "out" / "report.html").exists()
    data = json.loads((tmp_path / "out" / "findings.json").read_text())
    assert data["schema_version"] == 1
    assert data["summary"]["total"] == 0


def test_exit_2_on_critical_and_0_when_fail_on_never(tmp_path):
    from repoguard.runner import _exit_code
    crit = [Finding(id="X", title="t", severity="Critical", tool="test",
                    where="f:1", evidence="e", owasp="A01", fix="fix")]
    assert _exit_code(crit, "critical") == 2
    assert _exit_code(crit, "never") == 0


def test_live_unreachable_url_is_info_not_crash(tmp_path):
    ns = _args(FIXTURES / "empty_repo", output=str(tmp_path / "out2"),
               url="http://127.0.0.1:9")  # nothing listens here
    code = run_scan(ns)
    assert code == 0  # Info only
    data = json.loads((tmp_path / "out2" / "findings.json").read_text())
    assert any(f["id"] == "LIVE-UNREACHABLE" for f in data["findings"])


def test_report_writers_roundtrip(tmp_path):
    f = Finding(id="T-1", title="demo", severity="High", tool="test",
                where="a.py:3", evidence="snippet", owasp="A05:2021", fix="do x",
                file="a.py", line=3)
    rep = Report(target="t", base_url=None, generated_at="now",
                 summary=build_summary([f]), findings=[f], endpoints=[],
                 scanner_status={"test": "ok"})
    write_json(rep, tmp_path / "findings.json")
    write_html(rep, tmp_path / "report.html")
    assert "demo" in (tmp_path / "report.html").read_text()
    assert json.loads((tmp_path / "findings.json").read_text())["findings"][0]["id"] == "T-1"


def test_missing_path_returns_1(tmp_path):
    assert main(["scan", "/nonexistent-xyz-123", "--output", str(tmp_path)]) == 1
