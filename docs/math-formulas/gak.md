# GAK — Dynamic Substitution (Eyes / Noita model)

**Source:** [Null-H3x/Eyes](https://github.com/Null-H3x/Eyes) `eyestat/eyestat_kernels.py::gak_encrypt`, `gak_decrypt`.

GAK is **not** Gronsfeld autokey or mod-26 Vigenère addition. It is a **dynamic permutation cipher** over alphabet size \(N\):

\[
c_p = \text{active}_p[p_p]
\]

After each symbol, the active permutation advances by composing with a keyed permutation \(\sigma[k]\), where \(k\) is derived from the stream.

## Key material

PRNG seed → **\(N+1\)** permutations \(\sigma[0], \sigma[1], \ldots, \sigma[N]\) in \(S_N\):

- \(\sigma[0]\) = initial **active** permutation
- \(\sigma[1..N]\) = keyed update tables indexed by stream value \(k\)

## GAK modes (modes 0–3)

| Mode | Advance key \(k\) | Composition |
|------|-------------------|-------------|
| **ctak_right** | \(k = c_p\) | active ← active ∘ σ[k] |
| **ctak_left** | \(k = c_p\) | active ← σ[k] ∘ active |
| **ptak_right** | \(k = p_p\) | active ← active ∘ σ[k] |
| **ptak_left** | \(k = p_p\) | active ← σ[k] ∘ active |

**CTAK** = ciphertext-autokey permutation (like classical key-autokey on permutations).  
**PTAK** = plaintext-autokey permutation.

## This repo (mod 26 teaching instances)

| Slug | Mode | PRNG seed |
|------|------|-----------|
| `gak-ctak-right-s42` | ctak_right | 42 |
| `gak-ptak-right-s42` | ptak_right | 42 |

Implementation: `cipherops/ciphers/gak.py`

## Cryptanalysis (Eyes context)

- **Non-periodic** — no Vigenère period / coset IC pipeline
- Primary attack surface: **PRNG seed brute force** (EyeStat GPU runner)
- Noita corpus uses **N = 83**; teaching datasets use **N = 26**
- Structural probes: Eyes §227–237 (adjacent-different-σ, transition tables)

## See also

- [`xgak.md`](xgak.md) — extended modes using \((p+c)\) or \((c-p) \mod N\) as key index
- [`gronsfeld-autokey.md`](gronsfeld-autokey.md) — separate classical numeric autokey (not Eyes GAK)
- [`../math-formulas/noita-eye.md`](../math-formulas/noita-eye.md) — unsolved corpus
