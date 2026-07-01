# Pre-LLM Ingestion

This folder contains cryptographic training data, organized by ingestion stage and use case.

## 📂 Structure

```
Pre-LLM-Ingestion/
├── processed/                    # Audited, tokenizable ground truth
│   ├── cipher-ground-truth.jsonl # Cipher registry + math refs + dataset paths
│   └── cipher-qna-ground-truth.jsonl
├── instruction-tuning/           # Legacy starter instruction rows
│   ├── qwen-crypto-4.jsonl
│   └── qwen-crypto-additional.jsonl
└── README.md
```

## 📊 Ground Truth Audit

Ground truth is generated from validated implementations in `cipherops/ciphers/` and cross-linked to `docs/math-formulas/`:

```bash
PYTHONPATH=. python3 scripts/generate_ciphertext_properties.py
PYTHONPATH=. python3 scripts/validate_ciphertext_properties.py
PYTHONPATH=. python3 scripts/sync_repo.py              # regenerate + validate all
PYTHONPATH=. python3 scripts/sync_repo.py --refresh-eyes
PYTHONPATH=. python3 scripts/build_ground_truth.py
PYTHONPATH=. python3 scripts/generate_datasets.py
PYTHONPATH=. python3 scripts/validate_datasets.py
PYTHONPATH=. python3 scripts/import_eyes_corpus.py --clone   # refresh unsolved corpus
PYTHONPATH=. python3 scripts/comprehensive_validate.py
```

Each record in `processed/cipher-ground-truth.jsonl` includes:
- `cipher_family`, `variant_slug`, `params`
- `math_ref` (formula documentation path)
- `dataset_path` (validated plaintext/ciphertext pairs, or unsolved ciphertext)
- `audit_status`: `math_implementation_verified` (solved) or `unsolved_corpus_imported`
- `status`: `solved` or `unsolved`

## 📊 Datasets Overview

| Dataset | Use Case | Format | Size |
|---------|----------|--------|------|
| `processed/cipher-ground-truth.jsonl` | Pre-LLM cipher registry | JSONL | 47 solved + 1 unsolved |
| `datasets/fingerprinted/*/data.jsonl` | Plaintext/ciphertext pairs | JSONL | 10 samples × 47 ciphers |
| `datasets/ciphertext-properties/*/properties.jsonl` | Cryptanalytic metadata | JSONL | 479 property profiles |
| `datasets/unsolved/noita-eye-messages/data.jsonl` | Unsolved Noita eye puzzle | JSONL | 9 messages (no plaintext) |
| `instruction-tuning/qwen-crypto-*.jsonl` | General crypto Q&A (legacy) | JSONL | 8 items |

## 📜 License Notes

- **RFCs**: Public domain (IETF)
- **Wikipedia**: CC BY-SA 3.0
- **CTF write-ups**: Varies by author — check individual repos
- **NIST publications**: Public domain (US government)

Always verify licenses before training!
