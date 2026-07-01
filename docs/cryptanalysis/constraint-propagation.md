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

## Audit

```bash
PYTHONPATH=. python3 scripts/constraint_audit.py
```

Future: write `payload` to `datasets/constraint-findings/{corpus}/findings.jsonl`.
