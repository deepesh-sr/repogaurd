"""Shared live HTTP client: session, timeout, throttle, redacted evidence."""
from __future__ import annotations

import time
from dataclasses import dataclass


EVIDENCE_CAP = 1500
MIN_INTERVAL = 0.2  # <=5 req/s politeness (A4 burst bypasses)


@dataclass
class Resp:
    status: int
    headers: dict
    body: str
    url: str
    method: str


class LiveClient:
    def __init__(self, timeout: int = 10, token: str | None = None) -> None:
        import requests  # guaranteed by Dockerfile; stdlib fallback below
        self._req = requests
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "repoguard/0.1"})
        self.timeout = timeout
        self.token = token
        self._last = 0.0

    def _throttle(self) -> None:
        gap = time.time() - self._last
        if gap < MIN_INTERVAL:
            time.sleep(MIN_INTERVAL - gap)
        self._last = time.time()

    def request(self, method: str, url: str, token: str | bool | None = None,
                throttle: bool = True, **kw) -> Resp | None:
        """None on connection error/timeout (callers emit LIVE-UNREACHABLE).

        token=True uses the client's token; token=<str> uses that value.
        """
        if throttle:
            self._throttle()
        headers = dict(kw.pop("headers", {}) or {})
        use = self.token if token is True else token
        if use:
            headers["Authorization"] = f"Bearer {use}"
        try:
            r = self.session.request(method, url, headers=headers,
                                     timeout=self.timeout, allow_redirects=True, **kw)
            h = {k: v for k, v in r.headers.items()}
            body = r.text if isinstance(r.text, str) else ""
            return Resp(status=r.status_code, headers=h, body=body, url=url, method=method)
        except Exception as e:  # connection error / timeout -> None
            return None


def redact_url(url: str) -> str:
    return url  # tokens ride headers, never URLs, in v1


def evidence(resp: Resp) -> str:
    return (f"REQUEST: {resp.method} {redact_url(resp.url)} -> "
            f"RESPONSE: {resp.status} {resp.body[:EVIDENCE_CAP]}")[:2000]


def looks_like_data(resp: Resp) -> bool:
    """Lenient 'returned data' heuristic for A1 (PLAN: most common real API bug)."""
    if resp.status != 200 or len(resp.body.strip()) < 20:
        return False
    low = resp.body.lower()
    if any(m in low for m in ("unauthorized", "forbidden", "please log in",
                              "authentication credentials", "not authenticated")):
        return False
    return True


def similar(a: str, b: str, ratio: float = 0.8) -> bool:
    """Body similarity for A2 (method mirror) and A5 (IDOR)."""
    if not a or not b:
        return False
    if abs(len(a) - len(b)) > max(len(a), len(b)) * (1 - ratio) + 64:
        return False
    from difflib import SequenceMatcher
    return SequenceMatcher(None, a[:4000], b[:4000]).ratio() >= ratio


# --- error-leak signatures shared by L4 and A3 ---

LEAK_STACK = ["traceback (most recent call last)", "technical 500",
              "disallowedhost", "suspiciousoperation", "valueerror at ",
              "djangorestframework", "raise ", "during handling of the above"]
LEAK_SQL = ["select ", " syntax error", "psycopg2", "sqlite3.", "mysql",
            "ora-", "pg_query", "sqlalchemy"]
LEAK_PATH = [".py\", line ", "file \"", "/home/", "/app/", "/srv/", "c:\\"]


def find_leak(body: str) -> str | None:
    """Return 'stack' | 'sql' | 'path' if the body leaks internals, else None."""
    low = body.lower()
    if any(s in low for s in LEAK_STACK):
        return "stack"
    if any(s in low for s in LEAK_SQL):
        return "sql"
    if any(s in low for s in LEAK_PATH):
        return "path"
    return None
