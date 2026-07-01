# RSA-OAEP Hybrid Encryption

## Mathematical Definition

Hybrid construction for arbitrary-length messages:

1. Generate random AES key $K_{aes}$
2. Encrypt $K_{aes}$ with RSA-OAEP:
$$EK = \text{RSA-OAEP}_{(n,e)}(K_{aes})$$
3. Encrypt message with AES-GCM:
$$C = \text{AES-GCM}_{K_{aes}}(P)$$

RSA-OAEP padding (SHA-256):
$$\text{OAEP}(m) = m \oplus \text{MGF1}(r) \| r \oplus \text{MGF1}(\text{seed})$$

## Dataset

`datasets/fingerprinted/rsa-oaep-hybrid/data.jsonl`
