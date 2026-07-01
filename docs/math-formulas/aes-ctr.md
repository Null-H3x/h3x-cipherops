# AES-CTR (Counter Mode)

## Mathematical Definition

Stream cipher mode derived from AES block function:

$$\text{Keystream}_i = E_K(\text{Nonce} \| \text{Counter}_i), \quad C_i = P_i \oplus \text{Keystream}_i$$

## Dataset

`datasets/fingerprinted/aes-128-ctr/data.jsonl`
