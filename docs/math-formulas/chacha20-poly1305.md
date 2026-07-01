# ChaCha20-Poly1305

## Mathematical Definition

AEAD construction combining ChaCha20 stream cipher and Poly1305 MAC:

$$C = P \oplus \text{ChaCha20}_K(\text{nonce}), \quad T = \text{Poly1305}_{K'}(A, C)$$

256-bit key, 96-bit nonce (12 bytes), 128-bit tag.

## Dataset

`datasets/fingerprinted/chacha20-poly1305/data.jsonl`
