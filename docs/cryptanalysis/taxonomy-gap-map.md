# Cipher Taxonomy Gap Map

Cross-reference of **what this repo implements** vs **what classical/modern taxonomies name**, with priority tiers for closing gaps. Last updated after analyzer v1.2.0 (non-periodic polyalphabetic fix).

---

## Summary

| Layer | Count | Status |
|-------|-------|--------|
| Solved cipher variants (registry) | 57 | Implemented + dataset + math doc |
| Unsolved corpora | 1 (9 messages) | Noita eye |
| Ciphertext property profiles | 579 | Analyzer v1.2.0 |
| Math formula docs | 57 | One per implemented variant |
| `cipher-families.md` entries | ~35 named | ~12 not implemented |
| Extended taxonomy (81-type ref.) | ~81 | ~50+ not implemented |
| Executable cryptanalysis solvers | 0 | Metadata + stats only |

---

## Tier P0 — Implemented and audited

These have `cipherops` implementation, fingerprinted dataset, math doc, ground truth, and property profiles.

| Family | Variants | Difficulty | Cryptanalysis doc depth |
|--------|----------|------------|-------------------------|
| Atbash | 1 | 1 | Good (complement) |
| Caesar / ROT13 | 2 | 1 | Good |
| Affine | 1 | 3 | Good |
| Base64 | 1 | 1 | Encoding |
| Baconian | 1 | 2 | Encoding |
| **PAM-5 dibit** | 1 | 2 | **Encoding (line code)** |
| Vigenère | 1 | 3 | Good (periodic pipeline) |
| Beaufort | 1 | 3 | Good |
| Porta | 1 | 4 | Partial |
| Gronsfeld | 1 | 3 | Partial |
| **Autokey** | 2 | 4 | **Good (v1.2.0)** — non-periodic guidance |
| **Running key** | 1 | 4 | **Good (v1.2.0)** — non-periodic guidance |
| Substitution | 1 | 3 | Partial |
| Homophonic | 1 | 4 | Documented, no solver |
| Nomenclator | 1 | 3 | Partial |
| Polybius | 1 | 2 | Partial |
| Rail fence | 1 | 2 | Partial |
| Columnar | 1 | 3 | Partial |
| Playfair | 1 | 3 | Partial |
| Four-square | 1 | 4 | Partial |
| Hill (2×2) | 1 | 4 | Partial |
| ADFGX / ADFGVX | 2 | 5 | Partial |
| Bifid / Trifid | 2 | 4–5 | Partial |
| Straddle checkerboard | 1 | 5 | Partial |
| Fractionated Morse | 1 | 5 | encrypt_only |
| AES-GCM/CBC/CTR | 5 | 6 | Modern KATs |
| ChaCha20-Poly1305 | 1 | 6 | Modern |
| 3DES, Fernet, XOR stream | 3 | 4–6 | Modern |
| PBKDF2, HKDF | 2 | 6 | Modern |
| RSA, Ed25519, X25519 | 3 | 7 | Modern |
| SHA-256/512, SHA3, BLAKE2b, HMAC | 5 | 3–4 | One-way |

---

## Tier P1 — Recently implemented (v1.3.0)

| Cipher | Slug | Type |
|--------|------|------|
| **Pigpen** | `pigpen-standard` | Symbol substitution |
| **Scytale** | `scytale-d5` | Cylinder transposition (d=5) |
| **Nihilist** | `nihilist-31415` | Polybius + numeric key |
| **Hex (UTF-8)** | `hex-utf8` | Radix encoding |
| **Manchester IEEE** | `manchester-ieee` | Line coding |

---

## Tier P1 — Still unimplemented

Listed in [`../math-formulas/unimplemented-ciphers.md`](../math-formulas/unimplemented-ciphers.md) and [`../math-formulas/cipher-families.md`](../math-formulas/cipher-families.md) — **no** `CipherSpec` yet.

| Cipher | Type | Why it matters | Suggested next step |
|--------|------|----------------|---------------------|
| **Copiale** | Homophonic symbols | Famous unsolved-style corpus; homophonic scoring gap | Reference corpus import (like Noita) |
| **VIC** | Compound (sub + transp) | High difficulty Soviet cipher | Math doc + staged impl |
| **Grille** | Transposition | Physical constraint model | Optional (niche) |
| **DRYAD** | Stream / XOR | Military historical | Lower priority vs modern XOR |
| **M-94** | Cylinder | US WWII device | Similar to Scytale |
| **Wahlwort** | Codeword | Word-level substitution | Nomenclator extension |
| **Generic transposition** | Permutation | Umbrella category | Covered partially by rail/columnar/scytale |

**Priority recommendation:** Copiale/VIC as corpus or multi-stage projects; Base32/Base58 for encoding tier.

---

## Tier P1b — Encodings reference (partial implementation)

| Scheme | Status | Doc |
|--------|--------|-----|
| Base64, Baconian, **PAM-5 dibit**, **Hex**, **Manchester IEEE** | Implemented | [`encodings-catalog.md`](../math-formulas/encodings-catalog.md) |
| 4D-PAM5, NRZ, 8b/10b, Base32/58 | Reference only | same |

## Tier P2 — Extended taxonomy gaps (81-type reference)

From [@systemslibrarian/cipher-detective-ai](https://github.com/systemslibrarian/cipher-detective-ai) gap analysis — representative families **not** in registry:

| Category | Examples not implemented |
|----------|-------------------------|
| Symbol / visual | Masonic variants, dancing men, tic-tac-toe |
| Historical compound | VIC, Great cipher, Bazeries, Jefferson disk |
| Book / nomenclator | Book cipher (full), Alberti disk |
| Modern classical | Enigma (rotor), Purple, SIGABA |
| Steganography | Null cipher, acrostic, word position |
| Non-Latin | Cyrillic substitution, Japanese ciphers |

These are **documented as out-of-scope** unless a specific corpus or training need arises. The [`curated-sources.md`](curated-sources.md) 81-type list is for **classifier gap analysis**, not a commitment to implement all 81.

---

## Tier P3 — Cryptanalysis tooling gaps (post v1.2.0)

| Capability | Status | Notes |
|------------|--------|-------|
| IC, Friedman, Kasiski, χ², entropy | ✅ Implemented | Periodic ciphers |
| Coset IC | ✅ Implemented | Skipped for autokey/running key |
| `analysis_guidance` | ✅ **New v1.2.0** | Non-periodic warnings |
| Autokey / running key attacks | ✅ **Fixed v1.2.0** | No longer Vigenère template |
| Regime-aware keyspace | ✅ **New v1.2.0** | Seed vs OTP-like |
| MIC / column shift recovery | ❌ Documented only | Vigenère key recovery |
| Isomorph detection | ❌ Documented only | NBiermann algorithm |
| Crib-drag executor | ❌ Metadata slot | Noita depth logic not automated |
| Hill-climb / GA solvers | ❌ Metadata slot | |
| Cipher classifier (`classify.py`) | ❌ Roadmap | |
| Ciphertext-autokey variant | ✅ Implemented | `autokey-ciphertext`, `autokey-ciphertext-beaufort` |
| Gronsfeld autokey (plaintext / ciphertext) | ✅ Implemented | `gronsfeld-autokey-*` |
| Eyes GAK / XGAK (dynamic perm) | ✅ Implemented | `gak-*`, `xgak-*` (from [Eyes](https://github.com/Null-H3x/Eyes)) |
| Autokey seed brute helper | ✅ Implemented | `cipherops/analysis/autokey_solver.py` |
| Homophonic scoring engine | ❌ | Copiale / Zodiac-class |
| Book corpus for running key | ❌ External | Only fixed excerpt in dataset |

---

## Tier P4 — Training / Q&A gaps

| Gap | Impact |
|-----|--------|
| Q&A depth varies by family | Autokey/running key updated; others still pointer-heavy |
| No negative examples in datasets | e.g. "this is NOT Vigenère because IC≈0.067" |
| Attack metadata not validated by running solvers | Heuristic confidence only |
| No multi-label cipher classification labels | Classifier training blocked |

---

## Remaining knowledge gaps (reassessment)

### Closed or substantially improved in v1.2.0

- Autokey treated as periodic Vigenère in attack metadata → **fixed**
- Misleading coset IC on autokey/running key → **suppressed**
- Thin autokey/running key math docs → **expanded**
- No taxonomy gap document → **this file**

### Still open — high impact

1. **No executable solvers** — profiles describe attacks; nothing runs MIC, crib-drag, or book search.
2. **Classifier missing** — cannot route ciphertext to correct family automatically.
3. **Homophonic / Copiale** — taxonomy named, no implementation or unsolved corpus beyond references.
4. **9+ classical ciphers in `cipher-families.md`** — no code path (VIC, Copiale, …).
5. **Fractionated Morse decrypt lossy** — documented but limits roundtrip training on punctuation.

### Still open — medium impact

6. MIC and isomorph detection documented but not coded.
7. Running key lacks external book corpus tooling (only one embedded excerpt).
8. Per-cipher "Cryptanalysis Notes" uneven — strong for autokey/Vigenère, thin for Porta/Playfair/compound ciphers.
10. Noita unsolved — depth attack documented in Eyes repo, not automated here.

### Still open — lower impact

11. Extended 81-type taxonomy mostly unimplemented (expected).
12. Side-channel attack metadata generic for classical ciphers.
13. Q&A ground truth boilerplate for most families.

---

## Suggested roadmap order

```
1. classify.py heuristics (IC + period + symbol class → family hypothesis)
2. MIC implementation for periodic polyalphabetic only
3. Base32 / Base58 encodings (P1b quick wins)
4. Book corpus hook for running-key attack tooling
5. Isomorphs.py (NBiermann) for historical / Wheatstone-class
6. Copiale or homophonic corpus import
```

---

## How to regenerate this map

```bash
PYTHONPATH=. python3 -c "
from cipherops.ciphers.registry import CIPHER_REGISTRY
families = sorted({s.family for s in CIPHER_REGISTRY})
print(f'Implemented families ({len(families)}):', ', '.join(families))
print(f'Variants: {len(CIPHER_REGISTRY)}')
"
```

Cross-check against `docs/math-formulas/cipher-families.md` and [`curated-sources.md`](curated-sources.md).
