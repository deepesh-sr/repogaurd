"""T3a tests: L1-L4 app checks (mocked HTTP, no network)."""
from __future__ import annotations

import sys
from pathlib import Path

import requests_mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoguard.live import error_leak, exposed_paths, headers_cookies  # noqa: E402
from repoguard.live.http import LiveClient  # noqa: E402


BASE = "http://testserver"


def _client():
    c = LiveClient(timeout=5)
    c._last = 0  # disable throttle timing surprises (requests-mock is instant)
    import repoguard.live.http as h
    h.MIN_INTERVAL = 0
    return c


def test_l1_missing_headers():
    with requests_mock.Mocker() as m:
        m.get(BASE + "/", text="ok " * 20, headers={})
        findings, root = headers_cookies.check(BASE, _client())
    ids = {f.id for f in findings}
    assert "LIVE-HDR-CONTENT_SECURITY_POLICY" in ids
    assert "LIVE-HDR-X_FRAME_OPTIONS" in ids
    assert root is not None and root.status == 200


def test_l1_present_headers_no_findings():
    with requests_mock.Mocker() as m:
        m.get(BASE + "/", text="ok " * 20, headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff"})
        findings, _ = headers_cookies.check(BASE, _client())
    assert [f for f in findings if f.id.startswith("LIVE-HDR")] == []


def test_l2_cookie_without_flags():
    with requests_mock.Mocker() as m:
        m.get(BASE + "/", text="ok " * 20,
              headers={"Set-Cookie": "sessionid=abc123; Path=/",
                       "Content-Security-Policy": "x",
                       "Strict-Transport-Security": "x",
                       "X-Frame-Options": "x",
                       "X-Content-Type-Options": "x"})
        findings, _ = headers_cookies.check(BASE, _client())
    cookie_ids = {f.id for f in findings if f.id.startswith("LIVE-COOKIE")}
    assert "LIVE-COOKIE-SECURE-MISSING" in cookie_ids
    assert "LIVE-COOKIE-HTTPONLY-MISSING" in cookie_ids


def test_l3_exposed_git_and_admin():
    with requests_mock.Mocker() as m:
        m.get(BASE + "/", text="home " * 20)
        m.get(BASE + "/admin", text="<title>Log in | Django administration</title>" + "x" * 100)
        m.get(BASE + "/admin/", text="not found", status_code=404)
        m.get(BASE + "/.env", text="not here", status_code=404)
        m.get(BASE + "/.git/HEAD", text="ref: refs/heads/main\n")
        m.get(BASE + "/debug", text="nope", status_code=404)
        m.get(BASE + "/console", text="nope", status_code=404)
        m.get(BASE + "/server-status", text="nope", status_code=404)
        m.get(BASE + "/static/", text="nope", status_code=404)
        m.get(BASE + "/media/", text="nope", status_code=404)
        findings = exposed_paths.check(BASE, _client())
    ids = {f.id for f in findings}
    assert "LIVE-EXPOSED-ADMIN" in ids
    assert "LIVE-EXPOSED-_GIT_HEAD" in ids
    git_f = next(f for f in findings if f.id == "LIVE-EXPOSED-_GIT_HEAD")
    assert git_f.severity == "High"


def test_l3_version_header():
    with requests_mock.Mocker() as m:
        m.get(BASE + "/", text="home " * 20, headers={"Server": "gunicorn/21.2"})
        for p in ["/admin", "/admin/", "/.env", "/.git/HEAD", "/debug",
                  "/console", "/server-status", "/static/", "/media/"]:
            m.get(BASE + p, text="nope", status_code=404)
        findings = exposed_paths.check(BASE, _client())
    assert any(f.id == "LIVE-VERSION" and f.severity == "Low" for f in findings)


def test_l4_debug_page_leak():
    body = "Traceback (most recent call last): File \"/app/views.py\", line 10"
    with requests_mock.Mocker() as m:
        m.get(BASE + "/repoguard-nonexistent-xyz", text=body, status_code=500)
        findings = error_leak.check(BASE, _client())
    assert len(findings) == 1 and findings[0].severity == "High"


def test_l4_clean_404_no_findings():
    with requests_mock.Mocker() as m:
        m.get(BASE + "/repoguard-nonexistent-xyz", text="Not found, sorry!", status_code=404)
        m.get(BASE + "/repoguard-nonexistent-xyz?q={{7*7}}", text="Not found", status_code=404)
        findings = error_leak.check(BASE, _client())
    assert findings == []


def test_unreachable_returns_none():
    c = _client()
    assert c.request("GET", "http://127.0.0.1:9/") is None
