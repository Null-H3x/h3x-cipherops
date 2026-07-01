# HKDF (HMAC-Based Key Derivation)

## Mathematical Definition

Extract-and-expand key derivation (RFC 5869):

$$\text{HKDF-Extract}(salt, IKM) = \text{HMAC}(salt, IKM)$$
$$\text{HKDF-Expand}(PRK, info, L) = \text{expand to } L \text{ bytes}$$

## Dataset

`datasets/fingerprinted/hkdf-aes-gcm/data.jsonl`
