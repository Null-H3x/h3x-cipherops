# AES-GCM (Galois/Counter Mode)

## Mathematical Definition

AES-GCM combines counter-mode encryption with Galois-field authentication:

$$C = E_K(P \oplus \text{Keystream}) , \quad T = \text{GHASH}_H(A, C)$$

Where:
- $K$ = AES key (128 or 256 bits)
- $P$ = plaintext blocks
- $C$ = ciphertext
- $T$ = authentication tag (128 bits)
- $A$ = associated data (optional)

## Python Implementation

See `cipherops/ciphers/modern.py::aes_128_gcm_encrypt`, `aes_256_gcm_encrypt`.

## Dataset

- `datasets/fingerprinted/aes-128-gcm/data.jsonl`
- `datasets/fingerprinted/aes-256-gcm/data.jsonl`
