# HMAC-SHA256

## Mathematical Definition

Hash-based Message Authentication Code:

$$\text{HMAC}(K, M) = H\big((K \oplus opad) \| H((K \oplus ipad) \| M)\big)$$

One-way keyed digest; no decryption defined.

## Dataset

`datasets/fingerprinted/hmac-sha256/data.jsonl` (encrypt_only)
