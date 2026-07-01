# Pre-LLM Ingestion

This folder contains cryptographic training data, organized by ingestion stage and use case.

## 📂 Structure

```
Pre-LLM-Ingestion/
├── raw/                          # Original sources (LICENSED!)
│   ├── rfc_cryptospecs/         # RFCs on cryptography
│   ├── textbook_excerpts/       # Public domain excerpts
│   └── ctf_writeups/            # Community write-ups
├── processed/                    # Cleaned, tokenizable text
│   ├── crypto-text-corpus.txt   # 100K+ token corpus
│   └── cipher-qna.jsonl         # 250+ Q&A pairs
├── instruction-tuning/
│   ├── qwen-crypto-250.jsonl    # LLM-ready format
│   └── README.md                # Preprocessing notes
└── README.md
```

## 📊 Datasets Overview

| Dataset | Use Case | Format | Size |
|---------|----------|--------|------|
| `crypto-text-corpus.txt` | Continued pretraining | Raw text | ~150K tokens |
| `cipher-qna.jsonl` | Instruction tuning | JSONL | 250+ Q&A pairs |
| `rfc_cryptospecs/` | Protocol understanding | Raw RFCs | ~50 docs |

## 📜 License Notes

- **RFCs**: Public domain (IETF)
- **Wikipedia**: CC BY-SA 3.0
- **CTF write-ups**: Varies by author — check individual repos
- **NIST publications**: Public domain (US government)

Always verify licenses before training!
