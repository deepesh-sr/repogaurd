# PyGoat LIVE gap (not run — documented, not faked)

The PDF asks for a live scan against PyGoat's own compose stack. That requires
Docker, which is **not installed on this machine** (`docker: command not found`).

What was done instead:

- The full live pipeline (L1–L4, A1–A5) is proven against a real running server:
  see the M3 throwaway-Flask demo and the DRF live run in `../drf-sample/live/`.
- Static + discovery on PyGoat already surface the live-testable surface:
  132 endpoints, 69 of them `DISC-OPEN-ENDPOINT` — these are exactly what A1
  would probe with `--url`.

To reproduce on a Docker host:

```bash
docker compose build
docker compose up -d pygoat
docker compose run --rm repoguard scan /target --url http://pygoat:8000
# expected: API-UNAUTH-EXPOSURE Criticals on the DISC-OPEN endpoints above,
# missing-header findings (PyGoat ships DEBUG=True), debug-page leaks.
```

Do not treat the static-only PyGoat report as a clean bill of health for the
running app — the `fix_first` list is headed by config secrets precisely because
live exploitability could not be confirmed or denied here.
