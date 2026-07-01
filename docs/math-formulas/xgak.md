# XGAK — eXtended GAK (Eyes model)

**Source:** [Null-H3x/Eyes](https://github.com/Null-H3x/Eyes) `eyestat/eyestat_kernels.py` modes 4–7.

XGAK extends GAK by indexing \(\sigma[k]\) with a **combined** stream value instead of raw plaintext or ciphertext alone.

## XGAK modes (modes 4–7)

| Mode | Advance key \(k\) | Composition |
|------|-------------------|-------------|
| **xgak_sum_right** | \(k = (p + c) \mod N\) | active ← active ∘ σ[k] |
| **xgak_sum_left** | \(k = (p + c) \mod N\) | active ← σ[k] ∘ active |
| **xgak_diff_right** | \(k = (c - p) \mod N\) | active ← active ∘ σ[k] |
| **xgak_diff_left** | \(k = (c - p) \mod N\) | active ← σ[k] ∘ active |

The **numerical offset** \(k\) is computed per position from the current plaintext and ciphertext symbols — this is the “numerical keystream index” in the Eyes brute-force taxonomy, **not** a repeating additive key like Vigenère.

## vs GAK (CTAK/PTAK)

| | GAK CTAK/PTAK | XGAK |
|---|---------------|------|
| Key index | \(c\) or \(p\) alone | \((p+c)\) or \((c-p) \mod N\) |
| Eyes probes | §141 CT-feedback tables | §151 relaxed transition gauntlet |
| Near-identity σ | — | §230 XGAK slack census |

## This repo (mod 26)

| Slug | Mode | PRNG seed |
|------|------|-----------|
| `xgak-sum-right-s42` | xgak_sum_right | 42 |
| `xgak-diff-right-s42` | xgak_diff_right | 42 |

Implementation: `cipherops/ciphers/gak.py` with `mode=` parameter.

## Cryptanalysis notes (from Eyes)

- Deterministic transition tables \(T[\text{prev}, \text{class}] \rightarrow \text{next}\) are probed in §141/§151/§237
- XGAK allows **near-identity** σ entries on unused alphabet classes (§230)
- Full decrypt still requires recovering all \(N+1\) permutations or the PRNG seed

## See also

- [`gak.md`](gak.md) — base CTAK/PTAK modes
- Eyes `eyestat/WORKFLOW.md` — 8-mode GAK/xGAK family listing
