# AES-CBC (Cipher Block Chaining)

## Mathematical Definition

$$C_i = E_K(P_i \oplus C_{i-1}), \quad C_0 = IV$$

Decryption:
$$P_i = D_K(C_i) \oplus C_{i-1}$$

PKCS#7 padding is applied to the final block.

## Dataset

- `datasets/fingerprinted/aes-128-cbc/data.jsonl`
- `datasets/fingerprinted/aes-256-cbc/data.jsonl`
