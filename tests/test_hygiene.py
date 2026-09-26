"""T1b tests: hygiene checks (PLAN S5)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoguard.scanners.hygiene import HygieneAdapter, scan_tree  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
HYG = FIXTURES / "hygiene_repo"

print("[DEBUG:test] T1b hygiene module loaded")  # [DEBUG] println -- REMOVE in T6


def test_flags_env_key_dump():
    findings = scan_tree(HYG)
    by_where = {f.where: f for f in findings}
    assert ".env" in by_where and by_where[".env"].severity == "High"
    assert "server.key" in by_where and by_where["server.key"].severity == "High"
    assert "dump.sql" in by_where and by_where["dump.sql"].severity == "Medium"
    assert all("HYG-" in f.id and "A05" in f.owasp for f in findings)
    assert all("git rm --cached" in f.fix for f in findings)


def test_ignores_clean_files():
    findings = scan_tree(HYG)
    flagged = {f.where for f in findings}
    assert "clean.py" not in flagged and "notes.txt" not in flagged
    assert len(findings) == 3


def test_sniff_finds_renamed_key(tmp_path):
    (tmp_path / "mystery.dat").write_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n")
    (tmp_path / "ok.txt").write_text("hello world\n")
    findings = scan_tree(tmp_path)
    assert [f.where for f in findings] == ["mystery.dat"]
    assert findings[0].severity == "High"


def test_empty_dir_ok(tmp_path):
    assert scan_tree(tmp_path) == []


def test_adapter_never_raises():
    findings, status = HygieneAdapter().run(HYG)
    assert status.startswith("ok") and len(findings) == 3
    findings, status = HygieneAdapter().run(Path("/nonexistent-xyz"))
    assert "error" in status and findings == []
