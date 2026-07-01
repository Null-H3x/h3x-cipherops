# Brute-Force Keyspace Reference

Search space \(|K|\) for classical cipher families. Formulas are exact or standard approximations; implemented in `cipherops/analysis/keyspace.py` and surfaced in `attacks.*.key_space_estimate`.

**Convention:** Report log₂|K| for large spaces; exact integer when feasible.

---

## Substitution & monoalphabetic

| Cipher | \|K\| | Formula | Notes |
|--------|-------|---------|-------|
| Atbash | 1 | Fixed | Self-reciprocal complement |
| Caesar / ROT | 25 | \(26 - 1\) | Exclude shift 0 |
| Affine | 312 | \(\varphi(26) \times 26 = 12 \times 26\) | \(\gcd(a,26)=1\) |
| Simple substitution | 26! ≈ 4×10²⁶ | Permutations of alphabet | Frequency + hill-climb |
| Atbash-equivalent ROT | 1 per class | Complement ciphers collapse | See isomorphs doc |

---

## Polyalphabetic (period m, alphabet α)

| Cipher | \|K\| | Formula |
|--------|-------|---------|
| Vigenère | \(26^m\) | Key letters |
| Beaufort | \(26^m\) | Same key space, different combiner |
| Autokey | \(26^m\) seed + plaintext extension | Effective key grows |
| Running key | Book-dependent | Key = external text |
| Gronsfeld | \(10^m\) | Decimal digit shifts |
| Porta | \(13^m\) | Key pairs half-alphabet |
| One-time pad | \(26^n\) | Key length = message; intractable |

**Brute force:** Enumerate \(m\) (Kasiski/Friedman), then \(26^m\) or \(10^m\) per column.

---

## Polygraphic

| Cipher | \|K\| | Notes |
|--------|-------|-------|
| Playfair | ≈ 25! | 5×5 square from keyword |
| Four-square | ≈ (25!)² | Two keyed squares |
| Hill (2×2) | 157,248 | Invertible 2×2 matrices mod 26 |
| Hill (n×n) | Product formula | Matrices with \(\gcd(\det,26)=1\) |

---

## Transposition

| Cipher | \|K\| | Notes |
|--------|-------|-------|
| Rail fence (r rails) | Depends on n,r | Route enumeration |
| Columnar (k columns) | k! | Permutation of column order |
| Scytale (diameter d) | n/d variants | Cylinder period |

**Attack:** Factorial search mitigated by anagram scoring, not raw enumeration.

---

## Fractionated / compound

| Cipher | Stage keys | Combined |
|--------|------------|----------|
| ADFGX / ADFGVX | Polybius key + columnar key | Product of stage spaces |
| Bifid / Trifid | Polybius square from keyword | ≈ 25! + period |
| Straddle checkerboard | Layout + numeric codes | Layout-dependent |

---

## Encoding (not cryptographic keyspace)

| Scheme | \|K\| |
|--------|-------|
| Base64 | 1 (deterministic encode) |
| Baconian | 1 mapping + stego channel |

---

## Modern (dataset ciphers)

| Family | \|K\| | Notes |
|--------|-------|-------|
| AES-128 | 2¹²⁸ | NIST SP 800-38 series |
| AES-256 | 2²⁵⁶ | |
| RSA-1024 (dataset) | ~2¹²⁸ ops (factor n) | Deterministic primes in `modern.py` |
| SHA-256 preimage | 2²⁵⁶ | One-way |
| Ed25519 / X25519 | 2²⁵⁶ | Elliptic-curve discrete log |

---

## Noita eye (unsolved, deck N=83)

| Model | \|K\| | Notes |
|-------|-------|-------|
| Position keystream | \(83^T\) | T = max message length (137) |
| Periodic key length m | \(83^m\) | If periodic sub-hypothesis |
| PRNG seed | Implementation-dependent | NollaPRNG / Park–Miller hypotheses (Eyes repo) |

---

## Meet-in-the-middle (advanced)

For compound ciphers with independent stage keys \(K_1, K_2\):

\[
|K| = |K_1| \times |K_2| \quad\text{naive} \qquad |K_1| + |K_2| \quad\text{MITM}
\]

Documented for future multi-stage attack tooling; not implemented.

---

## Implementation

```python
from cipherops.analysis.keyspace import estimate_keyspace

estimate_keyspace("vigenere", params={"key": "KEY"})  # uses key length
estimate_keyspace("caesar", params={"shift": 3})
estimate_keyspace("affine", params={"a": 5, "b": 8})
```

Used by `cipherops/analysis/attacks.py` for `brute_force.key_space_estimate`.
