#!/bin/bash
# Screen-recording script for the submission video (run on a Docker host
# with a browser; ~4 minutes narrated). Each block is one "scene".
set -e
cd "$(dirname "$0")/.."

echo "=== 1/5 clean install ==="
pip install -e ".[dev]"
python -m pytest -q 2>&1 | tail -1

echo "=== 2/5 static scan (fixture repo) ==="
python -m repoguard scan ./tests/fixtures/vuln_repo --output /tmp/rg-demo-static

echo "=== 3/5 live scan (throwaway app + token) ==="
# Terminal B: python tests/fixtures/demo_app.py  (serves :8123)
python -m repoguard scan ./tests/fixtures/discovery_flask \
  --url http://localhost:8123 --token demo-token-123 --output /tmp/rg-demo-live || true

echo "=== 4/5 open the report ==="
# Open /tmp/rg-demo-live/report.html in the browser: narrate the fix-first
# panel (API-UNAUTH-EXPOSURE Critical first), the endpoint inventory table,
# and one finding card (severity / where / evidence / OWASP / fix).
echo "open file:///tmp/rg-demo-live/report.html"

echo "=== 5/5 proof evidence ==="
ls evidence/pygoat/static evidence/drf-sample/static evidence/drf-sample/live
