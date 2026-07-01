# LLM Cryptography

A modular toolkit for **training language models on cryptography** and building a **CipherOps CLI suite** — from fingerprinting unknown ciphertext to smart brute-force attacks.

---

## 🧠 Vision

> *Two parallel paths, converging at intelligence:*

1. **Model Fine-Tuning Pipeline**  
   Use `qwen3-coder-next` as a foundation and fine-tune it on:
   - Classical & modern ciphers (ROT, Vigenère, XOR, RSA, AES)
   - CTF-style problem solving
   - RFC cryptospecs & math notation

2. **CipherOps CLI Toolkit**  
   A composable set of tools for real-world cipher analysis:
   - `fingerprint` — entropy, IC, Kasiski exam, key length estimation
   - `classify` — heuristic detection (Caesar vs Vigenère vs Base64)
   - `decode` — known-cipher decoders (ROT13, Base*, XOR)
   - `convert` — hex ↔ base64 ↔ bin ↔ ASCII
   - `brute-force` — parallel search over key space

> 🔗 **LLM + CLI Synergy**: The fine-tuned model can guide ambiguous cases or generate decoding hints.

---

## 🚀 Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/Null-H3x/LLM-Cryptography.git
cd LLM-Cryptography

pip install -r requirements-validate.txt   # cipher + dataset validation only
# pip install -r requirements.txt          # full stack (ML fine-tuning)
```

### 2. Validate datasets

```bash
PYTHONPATH=. python3 scripts/comprehensive_validate.py
```

Regenerate everything (datasets, ground truth, validation):

```bash
PYTHONPATH=. python3 scripts/sync_repo.py
PYTHONPATH=. python3 scripts/sync_repo.py --refresh-eyes   # also refresh Eyes corpus
```

### 3. Try the CipherOps CLI (basic)

```bash
# Classify a ciphertext file
python -m cipherops.cli classify example_cipher.txt

# Convert hex to ASCII
echo "48656c6c6f" | python -m cipherops.cli convert --from hex --to ascii
```

### 4. Fine-Tune Qwen3-Coder (LoRA)

```bash
python scripts/finetune_lora_qwen3.py \
    --model_name "qwen/qwen3-coder-next" \
    --dataset datasets/crypto-instruct-50.jsonl \
    --output_dir checkpoints/lora-crypto-qwen
```

---

## 📂 Project Structure

```
LLM-Cryptography/
├── cipherops/              # CLI + crypto analysis modules
│   ├── ciphers/            # Validated classical & modern cipher implementations
│   ├── analysis/           # Ciphertext profiling (fingerprint, freq, Kasiski, attacks)
│   ├── fingerprint.py      # entropy, IC, Kasiski (re-exports analysis)
│   └── cli.py              # click-based entrypoint (`fingerprint`, `analyze`)
├── datasets/
│   ├── fingerprinted/          # Validated plaintext/ciphertext pairs (47 cipher variants)
│   ├── ciphertext-properties/  # Cryptanalytic metadata per ciphertext record
│   └── unsolved/               # Real-world unsolved ciphertext corpora
├── docs/math-formulas/         # Math definitions linked to cipher implementations
├── Pre-LLM-Ingestion/
│   └── processed/              # Audited ground-truth registry for pre-LLM ingestion
├── scripts/
│   ├── generate_datasets.py    # Regenerate validated fingerprinted datasets
│   ├── validate_datasets.py    # Roundtrip validation
│   ├── generate_ciphertext_properties.py  # Build property profiles
│   ├── validate_ciphertext_properties.py  # Validate property datasets
│   ├── import_eyes_corpus.py   # Import unsolved Noita eye corpus from Eyes repo
│   ├── sync_repo.py            # Regenerate datasets + ground truth + validate
│   ├── comprehensive_validate.py  # Full audit (solved + unsolved)
│   └── build_ground_truth.py   # Build Pre-LLM-Ingestion/processed corpus
├── requirements-validate.txt   # Minimal deps for CI / dataset validation
└── requirements.txt            # Full stack (ML fine-tuning + crypto)
```

---

## 📊 Datasets

| Corpus | Path | Records | Status |
|--------|------|---------|--------|
| Fingerprinted ciphers | `datasets/fingerprinted/*/data.jsonl` | 470 (47 × 10) | solved, roundtrip-verified |
| Ciphertext properties | `datasets/ciphertext-properties/*/properties.jsonl` | 479 | fingerprint, frequency, Kasiski, n-grams, attack surface |
| Noita eye messages | `datasets/unsolved/noita-eye-messages/data.jsonl` | 9 | unsolved (from [Eyes](https://github.com/Null-H3x/Eyes)) |
| Ground truth registry | `Pre-LLM-Ingestion/processed/cipher-ground-truth.jsonl` | 48 | audited |

Math docs for every cipher: `docs/math-formulas/`. Ground truth links ciphers → math → datasets → property profiles.

Analyze a ciphertext from the CLI:

```bash
python -m cipherops.cli analyze "Dlc aygmo zbsux jmh nswtq yzcb xfo pyjc byk." --family vigenere
python -m cipherops.cli analyze "..." --family vigenere --json-out
```

---

## 🛠️ Roadmap

- [x] `cipherops/fingerprint.py` — Shannon entropy & index of coincidence
- [x] Ciphertext properties dataset (fingerprint, frequency, Kasiski, n-grams, attack surface)
- [x] Classical cipher datasets (28 variants, math-validated)
- [x] Modern key cipher datasets (19 variants)
- [x] Unsolved Noita eye corpus (Eyes repo import)
- [x] Comprehensive validation + CI
- [ ] `cipherops/classify.py` — heuristic classifier for common ciphers
- [ ] Starter crypto Q&A dataset expansion
- [ ] LoRA fine-tune script (Qwen3-Coder + PEFT)
- [ ] LLM-guided brute-force hints (e.g., "Try key length 9")

---

## 🤝 Contributing

We welcome crypto-curious contributors!  
Open an issue or PR — label it `cipherops`, `ft`, or `docs`.

---

## 📜 License

MIT © Null-H3x  
See `LICENSE` file.
