# Manchester Encoding (IEEE 802.3)

## Mathematical Definition

Line code: each data bit expands to **two half-bits** (symbols) with a mid-bit transition.

| Data bit | Manchester symbols |
|----------|-------------------|
| 0 | `01` |
| 1 | `10` |

Payload is length-prefixed UTF-8 (4-byte big-endian length + bytes) before bit expansion — same framing as PAM-5 in this repo.

## Cryptanalysis

| Property | Value |
|----------|-------|
| Key space | 1 (encoding) |
| Rate | 2 symbols per data bit |
| Use | 10BASE-T Ethernet PHY (with other constraints) |

## Python Implementation

`cipherops/ciphers/encoding.py::manchester_encode`, `manchester_decode`

## Dataset

`datasets/fingerprinted/manchester-ieee/data.jsonl`

## References

- IEEE 802.3 Clause 14 (10 Mb/s) / 802.3 Manchester signaling
- [`encodings-catalog.md`](encodings-catalog.md)
