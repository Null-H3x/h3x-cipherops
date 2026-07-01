# Gronsfeld Cipher Family

Numeric-key Vigenère variant: each key digit \(d_i \in \{0,\ldots,9\}\) maps directly to a Caesar shift.

**Related:** [`gronsfeld-autokey.md`](gronsfeld-autokey.md) (non-periodic extension variants). **Not** the same as [Eyes GAK/xGAK](gak.md) (dynamic permutation ciphers).

---

## Periodic Gronsfeld (`gronsfeld-31415`)

\[
E_i(x) = (x + d_i) \mod 26, \quad d_i = \text{digit}_i(K)
\]

The numeric key repeats with period \(m = |K|\). Same cryptanalysis as Vigenère with shift alphabet \(\{0,\ldots,9\}\).

---

## Variant matrix (this repo)

| Slug | Mode | Key | Period |
|------|------|-----|--------|
| `gronsfeld-31415` | Periodic | `31415` | 5 |
| `gronsfeld-autokey-31415` | Plaintext-autokey | `31415` | Non-periodic |
| `gronsfeld-autokey-ct-31415` | Ciphertext-autokey | `31415` | Non-periodic |

Autokey variants: see [`gronsfeld-autokey.md`](gronsfeld-autokey.md).

---

## Python Implementation

| Function | Variant |
|----------|---------|
| `classical.gronsfeld`, `gronsfeld_decrypt` | Periodic |
| `classical.gronsfeld_autokey`, `gronsfeld_autokey_decrypt` | Autokey (`extension=` plaintext or ciphertext) |

---

## Datasets

- `datasets/fingerprinted/gronsfeld-31415/data.jsonl`
- `datasets/fingerprinted/gronsfeld-autokey-31415/data.jsonl`
- `datasets/fingerprinted/gronsfeld-autokey-ct-31415/data.jsonl`

---

## Cryptanalysis

| Mode | Attacks |
|------|---------|
| Periodic | Kasiski, Friedman, coset IC, MIC (as Vigenère with digit shifts) |
| Autokey | Seed brute \(10^{|K|}\), cribs — **not** periodic methods; see [`autokey.md`](autokey.md) |
