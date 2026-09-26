"""T3b tests: A1-A5 API checks (mocked HTTP, no network)."""
from __future__ import annotations

import sys
from pathlib import Path

import requests_mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoguard.live import api_tests  # noqa: E402
from repoguard.live.http import LiveClient  # noqa: E402
from repoguard.models import Endpoint  # noqa: E402

print("[DEBUG:test] T3b module loaded")  # [DEBUG] println -- REMOVE in T6

BASE = "http://testserver"

import repoguard.live.http as _h
_h.MIN_INTERVAL = 0


def _ep(path="/api/notes", methods=None):
    return Endpoint(path=path, methods=methods or ["GET"], view="NoteViewSet",
                    file="views.py", line=1, source="drf-router")


def _client(token=None):
    return LiveClient(timeout=5, token=token)


def test_a1_exposed_returns_critical():
    with requests_mock.Mocker() as m:
        m.get(BASE + "/api/notes", json=[{"id": 1, "text": "hello world data here"}])
        f = api_tests.check_a1(BASE, _client(), _ep(), None)
    assert f is not None and f.id == "API-UNAUTH-EXPOSURE" and f.severity == "Critical"


def test_a1_protected_silent():
    with requests_mock.Mocker() as m:
        m.get(BASE + "/api/notes", text="Unauthorized", status_code=401)
        assert api_tests.check_a1(BASE, _client(), _ep(), None) is None
        m.get(BASE + "/api/notes", text="Forbidden", status_code=403)
        assert api_tests.check_a1(BASE, _client(), _ep(), None) is None


def test_a2_undeclared_delete_flagged():
    body = '{"id": 1, "text": "some note content here!"}'
    with requests_mock.Mocker() as m:
        m.get(BASE + "/api/notes", text=body)
        m.delete(BASE + "/api/notes", text=body)
        m.post(BASE + "/api/notes", text="Method not allowed", status_code=405)
        out = api_tests.check_a2(BASE, _client(), _ep(methods=["GET"]))
    assert [f.id for f in out] == ["API-METHOD-DELETE"]
    assert out[0].severity == "High"


def test_a3_traceback_leak_flagged():
    with requests_mock.Mocker() as m:
        m.post(BASE + "/api/notes", text="Traceback (most recent call last): File \"/app/x.py\", line 1", status_code=500)
        out = api_tests.check_a3(BASE, _client(), _ep(methods=["POST"]))
    assert len(out) == 1 and out[0].id == "API-ERROR-LEAK" and out[0].severity == "High"


def test_a3_get_only_skipped():
    out = api_tests.check_a3(BASE, _client(), _ep(methods=["GET"]))
    assert out == []


def test_a4_single_finding_on_no_limit():
    with requests_mock.Mocker() as m:
        m.get(BASE + "/", text="ok " * 20)
        out = api_tests.check_a4(BASE, _client())
    assert len(out) == 1 and out[0].id == "API-NO-RATELIMIT"


def test_a4_silent_on_429():
    with requests_mock.Mocker() as m:
        m.get(BASE + "/", text="slow down", status_code=429)
        out = api_tests.check_a4(BASE, _client())
    assert out == []


def test_a5_idor_critical():
    body = '{"id": 1, "owner": "alice", "secret": "data-here-12345"}'
    with requests_mock.Mocker() as m:
        m.get(BASE + "/api/notes/1", text=body)
        f = api_tests.check_a5(BASE, _client(token="AAA"), _ep("/api/notes/{id}"), "BBB")
    assert f is not None and f.id == "API-IDOR" and f.severity == "Critical"
    assert "AAA" not in f.evidence and "BBB" not in f.evidence


def test_a5_silent_without_tokens():
    assert api_tests.check_a5(BASE, _client(), _ep("/api/notes/{id}"), None) is None


def test_a5_silent_on_403_for_other_user():
    with requests_mock.Mocker() as m:
        m.get(BASE + "/api/notes/1", [
            {"text": '{"id": 1, "owner": "alice data here"}'},
            {"text": "Forbidden", "status_code": 403}])
        # requests-mock serves responses in order per URL
        f = api_tests.check_a5(BASE, _client(token="AAA"), _ep("/api/notes/{id}"), "BBB")
    assert f is None
