# Constraint Propagation

Alphabet abstraction and three family-specific propagators that emit a shared **findings map** (hard pins, eliminations, derived assignments).

## Module

`cipherops/constraints/`

| Component | Role |
|-----------|------|
| `domain.py` | `AlphabetDomain`, `ConstraintState`, `FindingsMap`, `merge_findings()` |
| `shared_keystream.py` | Multi-message depth / shared `K[t]` (Noita model) |
| `stream_extension.py` | Autokey / Gronsfeld autokey crib + stream pins |
| `dynamic_perm.py` | GAK/XGAK seed verification + transition pins |

## Findings kinds

| Kind | Meaning |
|------|---------|
| `assignment` | Fixed symbol (pt, ct, seed, …) |
| `equality` | Same plaintext across messages at position |
| `keystream_pin` | Shared `K[t]` fixed |
| `pt_difference` | `\Delta pt` from ciphertext difference mod N |
| `stream_pin` | Autokey/GAK stream index at position |
| `seed_elimination` | PRNG seed ruled out |
| `seed_candidate` | Heuristic seed hit (brute + score) |
| `conflict` | Contradictory hard constraints |

Each finding carries `source`, `confidence` (`hard` \| `propagated` \| `heuristic`), and `data`.

## Usage

```python
from cipherops.constraints import (
    load_noita_state,
    propagate_shared_keystream,
    propagate_stream_extension,
    propagate_dynamic_perm,
    merge_findings,
)

# Noita depth
state = load_noita_state()
findings = propagate_shared_keystream(state)

# Autokey crib
from cipherops.constraints import propagate_from_crib_prefix
from cipherops.ciphers import classical
ct = classical.autokey("ATTACK", "KEY")
map = propagate_from_crib_prefix(ct, "ATTACK", seed_length=3, seed="KEY")

# GAK seed filter
from cipherops.constraints import AlphabetDomain, ConstraintState
state = ConstraintState(
    domain=AlphabetDomain(size=26),
    hypothesis={"mode": "ctak_right"},
    ciphertext=ct,
    plaintext_trial="HELLO",
    seed_candidates=[41, 42, 43],
)
gak_findings = propagate_dynamic_perm(state)

merged = merge_findings(findings, map, gak_findings)
payload = merged.to_dict()  # JSON-serializable
```

## Findings browser (H3X Dash)

In-browser dashboard for running the validated propagation loop on preset corpora, fingerprinted datasets, or pasted ciphertext:

```bash
PYTHONPATH=. python3 scripts/serve_constraints_dash.py
# → http://127.0.0.1:8765/
```

Features: preset corpus picker, fingerprinted autokey/GAK datasets, custom ciphertext paste, crib pins, round timeline, paginated findings table with filters.

Static assets live in `web/constraints-dash/`.

## Audit

```bash
PYTHONPATH=. python3 scripts/constraint_audit.py
```

## Findings pipeline

Validated findings are written under `datasets/constraint-findings/{corpus}/`:

| File | Contents |
|------|----------|
| `findings.jsonl` | All findings per round (with `round`, `fingerprint`) |
| `validated.jsonl` | Grounded validated subset |
| `history.json` | Round summaries, pins, convergence |

```bash
PYTHONPATH=. python3 scripts/generate_constraint_findings.py
PYTHONPATH=. python3 scripts/validate_constraint_findings.py
```

The generator runs propagators, **mathematically validates** each hard finding against source corpora, promotes validated pins into `ConstraintState`, and **re-propagates** until fixpoint (or max rounds). Rejected hard findings stop the loop and fail validation.

Programmatic loop:

```python
from cipherops.constraints.pipeline import build_corpus_configs, run_findings_loop

for config in build_corpus_configs("."):
    result = run_findings_loop(config, max_rounds=10)
    print(config.slug, result.converged, len(result.final_validated))
```
