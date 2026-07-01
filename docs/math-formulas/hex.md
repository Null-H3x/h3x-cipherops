# Hexadecimal Encoding

## Mathematical Definition

Maps each byte to two nybbles in radix 16:

\[
\text{Hex}(b) = \text{high\_nybble}(b) \,\|\, \text{low\_nybble}(b), \quad b \in [0,255]
\]

Output uses alphabet `0-9A-F` (uppercase in this implementation).

## Functions

- **E(P):** UTF-8 encode → `hex_encode` → uppercase nybble string  
- **D(C):** `hex_decode` → UTF-8 bytes → plaintext

| Property | Value |
|----------|-------|
| Key space | 1 (encoding) |
| Entropy | 4 bits per hex character |

## Python Implementation

`cipherops/ciphers/encoding.py::hex_encode`, `hex_decode`

## Dataset

`datasets/fingerprinted/hex-utf8/data.jsonl`
