"""T2 tests: Flask discovery (PLAN Part 2, D1-D4)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoguard.discovery.inventory import discover  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
FLASK = FIXTURES / "discovery_flask"

print("[DEBUG:test] T2 flask module loaded")  # [DEBUG] println -- REMOVE in T6


def test_flask_inventory_exact():
    endpoints, findings = discover(FLASK)
    by = {(e.path, tuple(e.methods)): e for e in endpoints}
    assert set(by) == {("/open", ("GET",)), ("/private", ("GET",)), ("/submit", ("POST",))}
    assert by[("/open", ("GET",))].view == "open_view"
    assert by[("/submit", ("POST",))].view == "submit_view"


def test_flask_protection_flags():
    endpoints, findings = discover(FLASK)
    by = {(e.path, tuple(e.methods)): e for e in endpoints}
    assert by[("/open", ("GET",))].protection == "open"
    assert by[("/private", ("GET",))].protection == "protected"
    assert "login_required" in by[("/private", ("GET",))].auth
    assert by[("/submit", ("POST",))].protection == "open"


def test_flask_findings():
    endpoints, findings = discover(FLASK)
    assert sorted(f.id for f in findings) == ["DISC-OPEN-ENDPOINT", "DISC-OPEN-ENDPOINT"]
    assert all(f.severity == "High" for f in findings)
