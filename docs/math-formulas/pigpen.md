# Pigpen Cipher (Masonic)

## Mathematical Definition

Monoalphabetic **symbol substitution**: each letter \(A..Z\) maps to a unique Pigpen / Masonic cell outline.

\[
E: \Sigma \to \mathcal{S}, \quad \mathcal{S} = \text{26 distinct cell symbols}
\]

This repo uses a fixed chart mapping letters to Unicode box-drawing symbols (see implementation).

## Cryptanalysis

| Property | Value |
|----------|-------|
| Key space | 1 (fixed chart) or \(26!\) if chart unknown |
| Attack | Frequency analysis on decoded letters; pattern matching on symbols |

## Python Implementation

`cipherops/ciphers/symbolic.py::pigpen_encode`, `pigpen_decode`

## Dataset

`datasets/fingerprinted/pigpen-standard/data.jsonl`

## Notes

- Case is not preserved through symbols; validation normalizes \(J \equiv I\) via Polybius convention on other ciphers.
- Punctuation and spaces are preserved in ciphertext.
