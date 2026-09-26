# DRF sample evidence runs (throwaway project, written for this proof)

Source: `/tmp/drf-sample/` (not committed — recreated from this file):
`settings.py` (DEBUG=True, hardcoded SECRET_KEY, ALLOWED_HOSTS=['*'] deliberate),
`views.py` (PublicNotes `AllowAny` = deliberately open; MyProfile + CreateNote
default `IsAuthenticated`), `urls.py`, `app.py` (migrate + demo user/token + runserver).
Django 5.2.17, DRF (TokenAuthentication), SQLite DB at `/tmp/drf-sample-db.sqlite3`
(outside the scanned tree so hygiene stays silent).

## Static

- Command: `python3 -m repoguard scan /tmp/drf-sample --output /tmp/rg-drf-static`
- Exit: 0. **8 findings**: CFG-01/02/03 (deliberate config), 1 DISC-OPEN-ENDPOINT
  (`GET /api/notes/`), CFG-06 ×2, bandit B105/B108 on the demo secret/token var.
- Discovery: exactly 3 endpoints — `GET /api/notes/` open, `POST /api/notes/create/`
  protected, `GET /api/profile/` protected (methods inferred from view handlers,
  auth inherited from the strict global default — the M5 discovery fixes).

## Live (`--url http://localhost:8124 --token <demo-token>`)

- Exit: **2**. **15 findings** (C 1 / H 4 / M 2 / L 8).
- `fix_first[0]` = **Critical API-UNAUTH-EXPOSURE on GET /api/notes/** — the
  deliberately-open endpoint, proven reachable without a token.
- Negative controls held: no A1 on `/api/profile/` (401 without token, 200 with),
  A2/A3 silent (405s dissimilar, clean error bodies), A4 single Low, L1 header
  findings + version note as expected on a dev server.
- The PDF's target chain is demonstrated: `DISC-OPEN-ENDPOINT` (static) →
  `API-UNAUTH-EXPOSURE` Critical (live) on the same route.
