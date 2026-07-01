# Autokey Cipher Family

Polyalphabetic ciphers where the keystream is **primed** by a short key, then **extended automatically** from the message. All variants in this family are **non-periodic** — do not apply Vigenère period recovery.

**Related:** [`gronsfeld-autokey.md`](gronsfeld-autokey.md) (Gronsfeld numeric autokey), [`gak.md`](gak.md) / [`xgak.md`](xgak.md) (Eyes dynamic permutation — separate family), [`../cryptanalysis/non-periodic-polyalphabetic.md`](../cryptanalysis/non-periodic-polyalphabetic.md).

---

## Variant matrix (this repo)

| Slug | Extension | Combiner | Priming key |
|------|-----------|----------|-------------|
| `autokey-standard` | Plaintext | Vigenère (+) | Alphabetic |
| `autokey-beaufort` | Plaintext | Beaufort (−) | Alphabetic |
| `autokey-ciphertext` | Ciphertext | Vigenère (+) | Alphabetic |
| `autokey-ciphertext-beaufort` | Ciphertext | Beaufort (−) | Alphabetic |
| `gronsfeld-autokey-31415` | Plaintext | Gronsfeld (+) | Numeric (see [`gronsfeld-autokey.md`](gronsfeld-autokey.md)) |
| `gronsfeld-autokey-ct-31415` | Ciphertext | Gronsfeld (+) | Numeric |

**Eyes GAK/xGAK** (dynamic permutation — separate family): [`gak.md`](gak.md), [`xgak.md`](xgak.md).

---

## Plaintext-autokey (text-autokey)

**Keystream (alphabetic seed):**

\[
k_i = \begin{cases}
K_i & i < |K| \\
p_{i-|K|} & i \geq |K|
\end{cases}
\]

**Encryption (standard):** \(E(p_i) = (p_i + k_i) \mod 26\)

**Beaufort:** \(E(p_i) = (k_i - p_i) \mod 26\)

---

## Ciphertext-autokey (key-autokey)

Historical variant: keystream extends with **prior ciphertext** letters.

\[
k_i = \begin{cases}
K_i & i < |K| \\
c_{i-|K|} & i \geq |K|
\end{cases}
\]

**Properties vs plaintext-autokey:**

- Receiver can decrypt with only priming key + ciphertext (no need to derive plaintext for extension).
- Single decryption error propagates to all subsequent positions.
- Crib-drag must align with ciphertext letters at extension offsets.

Implemented as `autokey-ciphertext` and `autokey-ciphertext-beaufort`.

---

## GAK / XGAK (Eyes — separate family)

Dynamic permutation ciphers from [Null-H3x/Eyes](https://github.com/Null-H3x/Eyes) — **not** Gronsfeld autokey. See [`gak.md`](gak.md) and [`xgak.md`](xgak.md). Gronsfeld numeric autokey: [`gronsfeld-autokey.md`](gronsfeld-autokey.md).

---

## Cryptanalysis (all variants)

Autokey family ciphers are **not periodic**. Do **not** apply Kasiski, Friedman, or coset IC for period recovery.

### Regimes

| Regime | Condition | IC behavior | Practical attack |
|--------|-----------|-------------|------------------|
| **Seed-dominated** | \(n \leq |K|\) | Low IC | Brute priming seed |
| **Mixed** | \(|K| < n \leq 2|K|\) | Transitional | Seed brute + prefix scoring |
| **OTP-like** | \(n \gg |K|\) | IC → English (~0.067) | Cribs / KPT only |

### Known-plaintext attack

Once \(p_j\) is known (plaintext-autokey or Gronsfeld plaintext-autokey):

\[
k_{j+|K|} = p_j \quad\text{or}\quad s_{j+m} = p_j \bmod 10
\]

For ciphertext-autokey (alphabetic or Gronsfeld), extension uses \(c_{j+|K|}\) from ciphertext.

### What does **not** work

- Kasiski period = \(|K|\)
- Friedman key-length on long messages
- Coset IC at seed length
- Per-column MIC as for periodic Vigenère

### Keyspace

| Variant | Seed space |
|---------|------------|
| Alphabetic autokey | \(26^{|K|}\) |
| Gronsfeld autokey | \(10^{|K|}\) |

See [`../cryptanalysis/keyspace-reference.md`](../cryptanalysis/keyspace-reference.md).

### Seed brute-force tooling

```python
from cipherops.analysis.autokey_solver import brute_force_autokey_seed, brute_force_gronsfeld_autokey_seed

candidates = brute_force_autokey_seed(ciphertext, seed_length=3, extension="plaintext")
gronsfeld_hits = brute_force_gronsfeld_autokey_seed(ciphertext, seed_length=5, extension="plaintext")
```

---

## Python Implementation

| Function | Variants |
|----------|----------|
| `classical.autokey`, `autokey_decrypt` | Alphabetic; `extension=` / `variant=` |
| `classical.gronsfeld_autokey`, `gronsfeld_autokey_decrypt` | Gronsfeld autokey (plaintext/ciphertext extension) |
| `analysis.autokey_solver.brute_force_*` | Seed enumeration helpers |

Property profiles set `analysis_guidance.periodicity = non_periodic` and omit `coset_ic`.

---

## Datasets

- `datasets/fingerprinted/autokey-standard/data.jsonl`
- `datasets/fingerprinted/autokey-beaufort/data.jsonl`
- `datasets/fingerprinted/autokey-ciphertext/data.jsonl`
- `datasets/fingerprinted/autokey-ciphertext-beaufort/data.jsonl`
- `datasets/fingerprinted/gronsfeld-autokey-31415/data.jsonl`
- `datasets/fingerprinted/gronsfeld-autokey-ct-31415/data.jsonl`
- `datasets/fingerprinted/gak-ctak-right-s42/data.jsonl`
- `datasets/fingerprinted/gak-ptak-right-s42/data.jsonl`
- `datasets/fingerprinted/xgak-sum-right-s42/data.jsonl`
- `datasets/fingerprinted/xgak-diff-right-s42/data.jsonl`

---

## References

- Wikipedia: [Autokey cipher](https://en.wikipedia.org/wiki/Autokey_cipher) (text-autokey vs key-autokey)
- Practical Cryptography: autokey + Gronsfeld
- Repo: [`../cryptanalysis/curated-sources.md`](../cryptanalysis/curated-sources.md)
