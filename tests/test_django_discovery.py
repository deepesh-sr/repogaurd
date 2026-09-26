"""T2 tests: Django/DRF discovery (PLAN Part 2, D1-D4)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoguard.discovery.inventory import discover  # noqa: E402
from repoguard.discovery.permissions import classify, parse_drf_default  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
DJANGO = FIXTURES / "discovery_django"



def _by_path(endpoints):
    return {(e.path, tuple(e.methods)): e for e in endpoints}


def test_drf_default_detected():
    assert parse_drf_default(DJANGO) == "AllowAny"


def test_django_inventory_exact():
    endpoints, findings = discover(DJANGO)
    by = _by_path(endpoints)
    assert ("/", ("GET",)) in by
    assert ("/dashboard/", ("GET",)) in by
    assert ("/public/", ("GET",)) in by
    # Router ViewSet expands to 5-route shape (6 method rows).
    assert ("/notes", ("GET",)) in by and ("/notes", ("POST",)) in by
    assert ("/notes/{id}", ("GET",)) in by
    assert ("/notes/{id}", ("DELETE",)) in by
    assert ("/notes/{id}", ("PUT",)) in by
    assert ("/notes/{id}", ("PATCH",)) in by
    assert len(endpoints) == 9


def test_django_protection_flags():
    endpoints, findings = discover(DJANGO)
    by = _by_path(endpoints)
    assert by[("/", ("GET",))].protection == "allowany-default"  # bare FBV, global AllowAny
    assert by[("/dashboard/", ("GET",))].protection == "protected"
    assert by[("/public/", ("GET",))].protection == "open"  # explicit AllowAny
    assert by[("/notes", ("GET",))].protection == "protected"
    assert by[("/notes/{id}", ("DELETE",))].protection == "protected"


def test_django_findings_one_per_endpoint():
    endpoints, findings = discover(DJANGO)
    ids = sorted(f.id for f in findings)
    assert ids == ["DISC-ALLOWANY-DEFAULT", "DISC-OPEN-ENDPOINT"]
    assert all(f.severity in ("High", "Medium") and "A01" in f.owasp for f in findings)
    open_f = next(f for f in findings if f.id == "DISC-OPEN-ENDPOINT")
    assert open_f.severity == "High" and "/public/" in open_f.title


def test_classifier_truth_table():
    assert classify(["IsAuthenticated"], [], None) == "protected"
    assert classify(["login_required"], [], None) == "protected"
    assert classify([], ["AllowAny"], None) == "open"
    assert classify([], [], "AllowAny") == "allowany-default"
    assert classify([], [], None) == "open"
    assert classify([], [], "IsAuthenticated") == "open"
    assert classify([], ["AllowAny"], "AllowAny") == "open"  # explicit open wins
