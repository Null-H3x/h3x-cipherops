# H3X Constraints Dash

Browser dashboard for the constraint findings pipeline (`propagate → validate → loop`).

## Run

```bash
chmod +x run.sh   # once
./run.sh
```

Or from repo root without the wrapper:

```bash
PYTHONPATH=. python3 scripts/serve_constraints_dash.py
```

Open [http://127.0.0.1:8765/](http://127.0.0.1:8765/) — use `./run.sh --lan` on a VM to reach the UI from your host browser.

## Workflow

1. **Source** — paste ciphertext (alphabetic, integer decks, etc.). Propagator and deck size start as **unknown**.
2. **Identify cipher** — scans statistics and ranks family hypotheses.
3. **Classification** — review hypotheses; click **Route → run** on one to apply propagator/deck routing and start the validated loop.
4. **Findings** — explore rows, apply crib pins, re-run after new pins (Loop options in Source).

Legacy preset/fingerprinted corpora remain available via the `/api/analyze` payload (`source: preset|fingerprinted|noita`) for scripts and tests.

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | Liveness |
| GET | `/api/sources` | Presets + fingerprinted slugs |
| POST | `/api/classify` | Heuristic family hypotheses + dash routing |
| POST | `/api/route-run` | Route a hypothesis + run validated loop |
| POST | `/api/analyze` | Run validated loop; returns session id |
| POST | `/api/crib-from-finding` | Crib pin suggestion from a finding row |
| GET | `/api/findings?session=…` | Paginated / filtered findings |

**Crib workflow:** click a `pt_difference` (or equality / keystream) row → **Apply crib pins**, or double-click a row to apply immediately. Stop suggestions with JSON examples are also clickable.

Each analyze response includes a **`stop`** object: `complete`, `needs_information`, `conflict`, etc., with prioritized suggestions when the loop hits a wall.

Uses Python stdlib `http.server` only — no extra web dependencies.
