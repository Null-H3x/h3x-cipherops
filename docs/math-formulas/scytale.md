# Scytale (Skytale)

## Mathematical Definition

Cylinder transposition attributed to Spartans. Plaintext is written in **rows** of width \(d\) (staff diameter), read down **columns**.

Let \(P\) have length \(n\), pad to \(n' = \lceil n/d \rceil \cdot d\). Matrix \(M\) is \(d \times (n'/d)\) filled row-major:

\[
C = \text{read\_columnwise}(M)
\]

**Decrypt:** write \(C\) column-major into \(M\), read row-major (strip padding `X`).

## Parameters

| Param | Dataset value |
|-------|---------------|
| `diameter` | 5 (`scytale-d5`) |

## Cryptanalysis

| Property | Value |
|----------|-------|
| Key | Staff diameter \(d\) |
| Search | Try small \(d\); anagram scoring on columns |
| IC | Preserved (~English) |

## Python Implementation

`cipherops/ciphers/transposition.py::scytale`, `scytale_decrypt`

## Dataset

`datasets/fingerprinted/scytale-d5/data.jsonl`
