# Non-Periodic Polyalphabetic Ciphers

Autokey (including ciphertext-autokey), Gronsfeld autokey, Eyes GAK/XGAK, and running key are polyalphabetic but **not periodic**. The standard Vigenère attack pipeline in [`methods.md`](methods.md) must **not** be applied blindly.

---

## Periodic vs non-periodic

| Property | Vigenère / Beaufort / Gronsfeld (periodic) | Autokey / Gronsfeld autokey / Eyes GAK·XGAK | Running key |
|----------|----------------------------------|----------------------|-------------|
| Keystream repeats | Yes, period \(m\) | No — extends with plaintext or ciphertext | No — external text |
| Kasiski useful | Yes | Misleading | No |
| Friedman period estimate | Yes | Misleading (often ≈ 1) | No |
| Coset IC | Confirms period | **Not applicable** | **Not applicable** |
| MIC column recovery | Yes | No | No |
| Long-text IC | ~0.038 (mod 26) | ~0.067 (English-like) | ~English if book is natural language |
| Primary attack | Period + shifts | Seed KPT / cribs | Book corpus + offset |

---

## Autokey workflow

```
Ciphertext
    → Check analysis_guidance.regime (seed_dominated | mixed | otp_like)
    → If short: brute-force 26^|K| seed, score prefix
    → If crib/KPT: iterative decrypt (each p_i extends keystream)
    → Do NOT run Kasiski / Friedman / coset IC for period
    → Long ciphertext-only: treat body as OTP-like
```

**Implementation:** `cipherops/analysis/guidance.py`, `attacks._autokey_attacks`

**Math:** [`../math-formulas/autokey.md`](../math-formulas/autokey.md)

---

## Running key workflow

```
Ciphertext
    → Reject periodic tools (same as autokey)
    → Attempt book crib / known passage match
    → Search candidate corpus at all offsets
    → Rank by language score / n-gram fit
    → Do NOT enumerate 26^m repeating keys
```

**Implementation:** `attacks._running_key_attacks`

**Math:** [`../math-formulas/running-key.md`](../math-formulas/running-key.md)

---

## Property profile fields

When `source.cipher_family` is `autokey`, `gak`, `xgak`, or `running_key`:

| Field | Value |
|-------|-------|
| `coset_ic` | `null` (omitted from scoring pipeline) |
| `analysis_guidance` | `periodicity: non_periodic`, warnings, recommended workflow |
| `attacks.brute_force` | Seed/corpus model — **not** `period-first enumeration` |

See [`../variable-inventory.md`](../variable-inventory.md) §5.

---

## Classifier note

Profiles for these families intentionally contradict generic polyalphabetic heuristics. The classifier and UI should:

1. Read `analysis_guidance` before recommending Kasiski/Friedman.
2. Autokey long-body IC near English is **expected**, not evidence of monoalphabetic substitution.
3. Running key breaks via **source identification**, not shift vectors.
