# Nihilist Cipher

## Mathematical Definition

Combine **Polybius square** coordinates with **numeric key addition mod 10** per digit.

1. Letter \(p \to (r,c)\) each 1..5 from keyed Polybius square  
2. Emit digits \(d_1 = r\), \(d_2 = c\)  
3. Key digits \(k_i\) from repeating numeric key:

\[
c_1 = (d_1 + k_i) \mod 10, \quad c_2 = (d_2 + k_{i+1}) \mod 10
\]

## Parameters (dataset)

| Param | Value |
|-------|-------|
| `numeric_key` | `31415` |
| `polybius_key` | `NIHILIST` |

## Cryptanalysis

| Property | Value |
|----------|-------|
| Key space | \(10^m \times \text{Polybius layout}\) |
| Attack | Divide into Polybius + Gronsfeld-style digit analysis |

## Python Implementation

`cipherops/ciphers/classical.py::nihilist`, `nihilist_decrypt`

## Dataset

`datasets/fingerprinted/nihilist-31415/data.jsonl`

## Notes

Polybius maps \(J \to I\); roundtrip validation normalizes \(J \equiv I\).
