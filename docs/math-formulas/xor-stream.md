# SHA-256 Counter-Mode XOR Stream

## Mathematical Definition

$$K_i = \text{SHA256}(K_{master} \| i), \quad C = P \oplus K$$

Counter-mode keystream derived from SHA-256 (educational stream cipher).

## Dataset

`datasets/fingerprinted/xor-sha256-stream/data.jsonl`
