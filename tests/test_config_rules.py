"""T1b tests: CFG-01..08 config rules (PLAN section 4)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoguard.scanners.django_flask_config import ConfigAdapter, scan_file  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"

print("[DEBUG:test] T1b config module loaded")  # [DEBUG] println -- REMOVE in T6


def _ids(findings):
    return sorted(f.id for f in findings)


def test_bad_settings_fires_all_rules():
    findings = scan_file(FIXTURES / "settings_bad.py")
    ids = _ids(findings)
    for rule in ["CFG-01", "CFG-02", "CFG-03", "CFG-04", "CFG-05", "CFG-06", "CFG-07"]:
        assert rule in ids, f"{rule} missing from {ids}"
    assert ids.count("CFG-05") == 2  # both middlewares missing
    assert len(findings) == 9
    by_id = {f.id: f for f in findings}
    assert by_id["CFG-01"].severity == "High"
    assert by_id["CFG-07"].severity == "High"
    assert all(f.file and f.line for f in findings)
    assert all("A05" in f.owasp for f in findings)


def test_cfg06_missing_is_low_explicit_false_is_medium():
    findings = scan_file(FIXTURES / "settings_bad.py")
    six = [f for f in findings if f.id == "CFG-06"]
    assert {f.severity for f in six} == {"Medium", "Low"}


def test_good_settings_zero_findings():
    assert scan_file(FIXTURES / "settings_good.py") == []


def test_flask_bad_fires_cfg08():
    findings = scan_file(FIXTURES / "flask_bad.py")
    assert _ids(findings) == ["CFG-08"]
    assert findings[0].severity == "High"


def test_flask_good_zero_findings():
    assert scan_file(FIXTURES / "flask_good.py") == []


def test_tricky_negatives():
    import ast
    from repoguard.scanners import django_flask_config as c
    tree = ast.parse('SECRET_KEY = os.environ["SECRET_KEY"]\n')
    assigns = c._top_assigns(tree)
    assert c.check_CFG_03(assigns, "x", Path("s.py")) == []
    tree = ast.parse("ALLOWED_HOSTS = []\n")
    assert c.check_CFG_02(c._top_assigns(tree), "x", Path("s.py")) == []
    tree = ast.parse('SECRET_KEY = ""\n')
    assert c.check_CFG_03(c._top_assigns(tree), "x", Path("s.py")) == []


def test_adapter_never_raises_and_status():
    findings, status = ConfigAdapter().run(FIXTURES)
    assert status.startswith("ok")
    assert any(f.id == "CFG-01" for f in findings)
    findings, status = ConfigAdapter().run(Path("/nonexistent-xyz"))
    assert "error" in status and findings == []
