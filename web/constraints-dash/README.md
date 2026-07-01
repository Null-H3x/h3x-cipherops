# H3X Constraints Dash

Browser dashboard for the constraint findings pipeline (`propagate → validate → loop`).

## Run

```bash
PYTHONPATH=. python3 scripts/serve_constraints_dash.py
```

Open [http://127.0.0.1:8765/](http://127.0.0.1:8765/)

## Input modes

| Mode | Description |
|------|-------------|
| **Preset corpus** | Built-in constraint-findings corpora (Noita, autokey, GAK demos) |
| **Fingerprinted dataset** | Autokey / GAK variants from `datasets/fingerprinted/` |
| **Noita eyes** | Full unsolved nine-message deck |
| **Paste ciphertext** | Custom autokey, GAK, or integer deck JSON |

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | Liveness |
| GET | `/api/sources` | Presets + fingerprinted slugs |
| POST | `/api/analyze` | Run validated loop; returns session id |
| GET | `/api/findings?session=…` | Paginated / filtered findings |

Each analyze response includes a **`stop`** object: `complete`, `needs_information`, `conflict`, etc., with prioritized suggestions when the loop hits a wall.

Uses Python stdlib `http.server` only — no extra web dependencies.
