# Unsolved Ciphertext Corpora

Real-world ciphertext with **no known plaintext**, imported from external research repos for CipherOps benchmarking and puzzle solving.

| Corpus | Source | Records | Status |
|--------|--------|---------|--------|
| Noita Eye Messages | [Null-H3x/Eyes](https://github.com/Null-H3x/Eyes) | 9 | unsolved |

## Import / Refresh

```bash
PYTHONPATH=. python3 scripts/import_eyes_corpus.py --clone
PYTHONPATH=. python3 scripts/build_cipher_registry.py
PYTHONPATH=. python3 scripts/comprehensive_validate.py
```

See `manifest.json` for paths and counts.
