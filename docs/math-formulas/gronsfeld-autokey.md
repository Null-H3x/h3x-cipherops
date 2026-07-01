# Gronsfeld Autokey (classical — not Eyes GAK)

Numeric priming key + plaintext/ciphertext shift extension over mod-26 addition. **Distinct** from the [Eyes GAK/xGAK](gak.md) dynamic permutation model used in Noita cryptanalysis.

---

## Variant matrix (this repo)

| Slug | Extension | Seed | Shift source after seed |
|------|-----------|------|-------------------------|
| `gronsfeld-autokey-31415` | Plaintext | `31415` | \(p_{i-5} \mod 10\) |
| `gronsfeld-autokey-ct-31415` | Ciphertext | `31415` | \(c_{i-5} \mod 10\) |

Both use Gronsfeld combiner \(E(p_i) = (p_i + s_i) \mod 26\) with \(s_i \in \{0,\ldots,9\}\).

---

## Plaintext-autokey (`gronsfeld-autokey-31415`)

\[
s_i = \begin{cases} d_i & i < m \\ p_{i-m} \mod 10 & i \geq m \end{cases}, \quad E(p_i) = (p_i + s_i) \mod 26
\]

Known-plaintext extension: once \(p_j\) is known, \(s_{j+m} = p_j \mod 10\).

---

## Ciphertext-autokey (`gronsfeld-autokey-ct-31415`)

\[
s_i = \begin{cases} d_i & i < m \\ c_{i-m} \mod 10 & i \geq m \end{cases}
\]

Extension uses prior **ciphertext** letters. Single decrypt error propagates; cribs must align with ciphertext at extension offsets.

---

## Cryptanalysis

Non-periodic — same regime model as [`autokey.md`](autokey.md):

| Regime | Attack |
|--------|--------|
| Seed-dominated (\(n \leq m\)) | Brute numeric seed \(10^m\) |
| Mixed | Seed brute + English scoring on prefix |
| OTP-like (\(n \gg m\)) | Cribs / KPT only |

Do **not** apply Kasiski, Friedman, or coset IC for period recovery.

### Seed brute-force tooling

```python
from cipherops.analysis.autokey_solver import brute_force_gronsfeld_autokey_seed

hits = brute_force_gronsfeld_autokey_seed(ciphertext, seed_length=5, extension="plaintext")
```

Seed space: \(10^{|K|}\). See [`../cryptanalysis/keyspace-reference.md`](../cryptanalysis/keyspace-reference.md).

---

## Python Implementation

`cipherops/ciphers/classical.py::gronsfeld_autokey`, `gronsfeld_autokey_decrypt`

Property profiles set `analysis_guidance.periodicity = non_periodic` and omit `coset_ic`.

---

## Datasets

- `datasets/fingerprinted/gronsfeld-autokey-31415/data.jsonl`
- `datasets/fingerprinted/gronsfeld-autokey-ct-31415/data.jsonl`

Periodic Gronsfeld (repeating key): [`gronsfeld.md`](gronsfeld.md).
