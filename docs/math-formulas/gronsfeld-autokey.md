# Gronsfeld AutoKey (classical — not Eyes GAK)

Numeric priming key + plaintext/ciphertext shift extension. **Distinct** from the [Eyes GAK/xGAK](gak.md) dynamic permutation model used in Noita cryptanalysis.

## Plaintext-autokey (`gronsfeld-autokey-31415`)

\[
s_i = \begin{cases} d_i & i < m \\ p_{i-m} \mod 10 & i \geq m \end{cases}, \quad E(p_i) = (p_i + s_i) \mod 26
\]

## Ciphertext-autokey (`gronsfeld-autokey-ct-31415`)

\[
s_i = \begin{cases} d_i & i < m \\ c_{i-m} \mod 10 & i \geq m \end{cases}
\]

## Implementation

`cipherops/ciphers/classical.py::gronsfeld_autokey`, `gronsfeld_autokey_decrypt`

## Cryptanalysis

Non-periodic — same regime model as [`autokey.md`](autokey.md). Seed space \(10^m\).
