# Fernet (Symmetric Authenticated Encryption)

## Mathematical Definition

High-level token format combining AES-128-CBC and HMAC-SHA256:

$$\text{Token} = \text{Version} \| \text{Timestamp} \| IV \| E_{K_{enc}}(P) \| \text{HMAC}_{K_{mac}}(\text{Header} \| C)$$

## Dataset

`datasets/fingerprinted/fernet/data.jsonl`
