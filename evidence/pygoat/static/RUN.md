# PyGoat static evidence run

- Target: `https://github.com/adeyosemanputra/pygoat` @ `19d17cc` (full clone, 2026-09-26)
- Command: `python3 -m repoguard scan /tmp/pygoat --output /tmp/pygoat/repoguard-report`
- Exit: 0 (no Critical — static only; live-exposure Criticals need `--url`)
- Result: **134 findings** (H 81 / M 15 / L 38), **132 endpoints discovered**

## What fired (headlines)

- `fix_first`: CFG-03 (hardcoded SECRET_KEY) ×2, CFG-01 (DEBUG=True) ×2, then DISC-OPEN-ENDPOINT ×8
- Discovery: 132 endpoints, **69 DISC-OPEN-ENDPOINT** (PyGoat views carry no auth — expected for a vuln-training app)
- Bandit 55: B105 hardcoded passwords ×18, B602 shell=True ×2, B324 weak hash ×3, B110/B106/B113/B311
- Config 10: CFG-01 ×2, CFG-03 ×2, CFG-06 ×4, CFG-02/CFG-05
- Hygiene 0 (no committed secrets/keys/dumps at HEAD)

## Honest gaps in this report (not hidden)

- `pip-audit`: **error, not clean** — its dependency resolution fails on PyGoat's pins
  (Pillow won't build under Python 3.14), so 0 findings were audited. Status row reads
  `error (audit failed: ...)`. This failure mode was found during this run and fixed
  in `repoguard/scanners/pip_audit.py` (previously misreported as `ok (0 findings)`),
  with regression test `test_pip_audit_resolution_failure_is_error_not_clean`.
  On a Docker host (Python 3.11) resolution is expected to succeed.
- `semgrep`, `gitleaks`: `missing (binary not installed)` — not installed on this machine;
  bundled in the Dockerfile for Docker-host runs.
- Live scan: not run (no Docker on this machine) — see `../LIVE-GAP.md`.
