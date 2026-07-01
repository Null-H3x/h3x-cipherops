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

pip install -r requirements.txt
```

### 2. Try the CipherOps CLI (basic)

```bash
# Classify a ciphertext file
python -m cipherops.cli classify example_cipher.txt

# Convert hex to ASCII
echo "48656c6c6f" | python -m cipherops.cli convert --from hex --to ascii
```

### 3. Fine-Tune Qwen3-Coder (LoRA)

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
│   ├── __init__.py
│   ├── fingerprint.py      # entropy, IC, Kasiski
│   ├── classify.py         # heuristic classifier
│   ├── decode.py           # decoders (ROT, Base*, XOR)
│   ├── convert.py          # encoding conversions
│   ├── brute_force.py      # parallel key search
│   └── cli.py              # click-based entrypoint
├── datasets/
│   └── crypto-instruct-50.jsonl  # starter Q&A dataset
├── scripts/
│   ├── finetune_lora_qwen3.py  # SFTTrainer script
│   └── evaluate_cipher_decoder.py
├── docs/                   # fine-tuning guides, model cards
├── requirements.txt
└── README.md
```

---

## 🛠️ Roadmap

- [ ] `cipherops/fingerprint.py` — Shannon entropy & index of coincidence
- [ ] `cipherops/classify.py` — heuristic classifier for common ciphers
- [ ] Starter crypto Q&A dataset (50 items)
- [ ] LoRA fine-tune script (Qwen3-Coder + PEFT)
- [ ] LLM-guided brute-force hints (e.g., "Try key length 9")
- [ ] CI/CD for eval benchmarking on known ciphers

---

## 🤝 Contributing

We welcome crypto-curious contributors!  
Open an issue or PR — label it `cipherops`, `ft`, or `docs`.

---

## 📜 License

MIT © Null-H3x  
See `LICENSE` file.
