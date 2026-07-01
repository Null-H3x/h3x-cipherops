# Classical Cryptanalysis Reference

Grounded reference material for statistical attacks, keyspace enumeration, structural patterns (isomorphs), and complement ciphers. Formulas cross-checked against standard sources (Friedman 1920s, Kasiski 1863, Wikipedia/academic summaries) and open implementations on GitHub.

## Contents

| Document | Topics |
|----------|--------|
| [`methods.md`](methods.md) | Index of coincidence, Friedman test, Kasiski examination, coset IC, χ², Shannon entropy |
| [`keyspace-reference.md`](keyspace-reference.md) | Brute-force search space \|K\| per cipher family |
| [`isomorphs-and-complements.md`](isomorphs-and-complements.md) | Isomorph patterns, complement/reciprocal ciphers, equivalence classes |
| [`curated-sources.md`](curated-sources.md) | Vetted GitHub repos and papers used for validation |

## Implementation mapping

| Doc topic | Code |
|-----------|------|
| IC, Friedman, χ², entropy | `cipherops/analysis/fingerprint.py` |
| Kasiski | `cipherops/analysis/kasiski.py` |
| Coset IC | `cipherops/analysis/coset_ic.py` |
| Keyspace estimates | `cipherops/analysis/keyspace.py` |
| Attack viability metadata | `cipherops/analysis/attacks.py` |
| Full profiles | `cipherops/analysis/profile.py` → `datasets/ciphertext-properties/` |

## Related

- [`../math-formulas/definitions.md`](../math-formulas/definitions.md) — P, C, K notation
- [`../variable-inventory.md`](../variable-inventory.md) — all dataset fields
