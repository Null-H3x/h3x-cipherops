# Knowledge Gaps — Living Assessment

Snapshot of what the repo knows vs what it can **do**. Updated after analyzer **v1.2.0** (non-periodic polyalphabetic fix, taxonomy map, expanded autokey/running-key docs).

For cipher coverage see [`taxonomy-gap-map.md`](taxonomy-gap-map.md). For attack formulas see [`methods.md`](methods.md).

---

## Maturity model

| Level | Meaning | Example |
|-------|---------|---------|
| **L4** | Implement + audit + correct cryptanalysis metadata + teaching docs | Autokey, Vigenère, Caesar |
| **L3** | Implement + audit + dataset; cryptanalysis partial or generic | Playfair, Porta, Hill |
| **L2** | Implement + audit only | Most modern ciphers |
| **L1** | Named in taxonomy, not implemented | Pigpen, VIC, Copiale |
| **L0** | Referenced externally only | 81-type long tail |

---

## By layer

### Implementation & math (strong)

- 47 solved variants with roundtrip validation and math docs
- Deep math audit (`scripts/math_audit.py`) on KATs and full corpus
- Ground truth registry links math ↔ data ↔ properties

**Gap:** 12+ classical ciphers named in `cipher-families.md` without code.

### Statistical analysis (good, with caveats)

- Fingerprint, Kasiski, coset IC, n-grams, patterns — production-ready
- **v1.2.0:** `analysis_guidance` flags when periodic tools mislead
- **v1.2.0:** autokey/running key skip coset IC; dedicated attack profiles

**Gap:** Friedman/Kasiski still computed for non-periodic ciphers (values present but flagged misleading in `analysis_guidance.warnings`). Future: optional `kasiski: null` for those families.

### Attack execution (weak)

- Six attack vectors are **schema + heuristics**, not runnable tools
- No MIC, no isomorph detector, no book search, no crib-drag engine

**Gap:** Largest practical hole for "CipherOps" product vision.

### Property profile coverage (improving)

- Consistent schema across fingerprinted and unsolved records
- Autokey docs now teach non-periodic behavior
- No negative/contrastive examples (Vigenère vs autokey same IC regime)

**Gap:** Classifier labels, solver-verified attack outcomes, richer Q&A per family.

### Unsolved corpora (narrow but deep)

- Noita eye: imported, validated, documented
- No automated depth/crib solver

**Gap:** Second unsolved corpus (e.g. Copiale) would diversify training.

---

## Autokey / running key status (v1.2.0)

| Concern | Before | After |
|---------|--------|-------|
| Attack metadata | Vigenère template | Family-specific |
| Coset IC | Computed (misleading) | Omitted |
| Keyspace label | `26^3` only | Seed + OTP-like regimes |
| Math docs | ~28 lines | Full cryptanalysis sections |
| Math audit KATs | None | Added |
| `analysis_guidance` | None | Regime + warnings |

**Remaining autokey gaps:** automated seed brute-force now available (`cipherops/analysis/autokey_solver.py`); Friedman/Kasiski values still in profile (with warnings). Ciphertext-autokey, GAK, and XGAK implemented.

---

## Top 5 gaps to close next

1. **`classify.py`** — route by IC, periodicity hints, symbol class
2. **MIC solver** — periodic polyalphabetic key recovery (Vigenère class only)
3. **Pigpen + Scytale** — P1 taxonomy, low implementation cost
4. **Suppress or annotate misleading metrics** — null Kasiski/Friedman when `analysis_guidance` says so
5. **Contrastive training pairs** — same plaintext under Vigenère vs autokey with labeled analysis

---

## Related documents

| Doc | Purpose |
|-----|---------|
| [`taxonomy-gap-map.md`](taxonomy-gap-map.md) | Implemented vs named vs 81-type gaps |
| [`non-periodic-polyalphabetic.md`](non-periodic-polyalphabetic.md) | Autokey / running key truth |
| [`../math-formulas/autokey.md`](../math-formulas/autokey.md) | Autokey math + attacks |
| [`../variable-inventory.md`](../variable-inventory.md) | `analysis_guidance` field |
