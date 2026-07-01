# H3X CipherOps

An **HTML-based cryptographic puzzle solver** backed by a validated cipher engine (`cipherops/`). Paste or select ciphertext in the browser, identify the likely family, run constraint propagation and attacks, and iterate until the math grounds out or hits a wall with actionable next steps.

The primary stress test is **[Noita Eyes](https://github.com/Null-H3x/Eyes)** — nine unsolved multi-message ciphertexts with a shared depth keystream. Solving Eyes is the byproduct of building a solver robust enough to handle arbitrary puzzle inputs, not the other way around.

---

## Vision

> **Identify → hypothesize → propagate → validate → attack → repeat**

1. **Web solver (main product)**  
   Browser UI for real cryptanalysis sessions: fingerprint unknown text, pick or auto-suggest a cipher family, run propagators and decoders, pin cribs, and watch findings converge (or stop with suggestions).

2. **Validated cipher engine (`cipherops/`)**  
   77+ reversible cipher implementations, statistical profiling, and **constraint propagators** that emit mathematically checkable findings — not LLM guesses.

3. **Optional LLM layer (later)**  
   A model may propose cribs or hypotheses; the engine accepts or rejects them. This repo does not treat constraint-findings JSONL as training data — it is too sparse and repetitive for fine-tuning.

---

## Quick start

### 1. Clone and install

```bash
git clone https://github.com/Null-H3x/h3x-cipherops.git
cd h3x-cipherops
chmod +x run.sh
./run.sh
```

Or from a **zip extract** — unzip, `cd` into the folder, then `./run.sh` (creates `.venv`, installs deps, starts the UI).

```bash
chmod +x run.sh          # once, if needed
./run.sh                 # http://127.0.0.1:8765/
./run.sh --lan           # VM / LAN: http://<your-ip>:8765/
./run.sh --validate      # audit engine, then start UI
./run.sh --setup-only    # install only, don't start server
```

Manual install (optional):

```bash
pip install -r requirements-validate.txt
```

### 2. Run the puzzle solver UI

```bash
./run.sh
# or: PYTHONPATH=. python3 scripts/serve_constraints_dash.py
```

Open [http://127.0.0.1:8765/](http://127.0.0.1:8765/)

| Input | Use for |
|-------|---------|
| **Paste ciphertext** | Autokey, GAK, custom decks |
| **Noita eyes** | Nine-message shared-keystream puzzle |
| **Fingerprinted dataset** | Known-family regression / demos |
| **Preset corpus** | Validated propagation smoke tests |

Workflow: run analysis → review **stop report** (`complete` vs `needs_information`) → click `pt_difference` rows to **auto-fill crib pins** → re-run until keystream or seed grounds.

See [`web/constraints-dash/README.md`](web/constraints-dash/README.md) for API details.

### 3. CLI (headless / scripting)

```bash
# Entropy and index of coincidence
python -m cipherops.cli fingerprint "Dlc aygmo zbsux jmh nswtq yzcb xfo pyjc byk."

# Full property profile (Kasiski, n-grams, attack surface)
python -m cipherops.cli analyze "..." --family vigenere --json-out
```

### 4. Validate the engine (developers)

```bash
PYTHONPATH=. python3 scripts/comprehensive_validate.py
PYTHONPATH=. python3 scripts/constraint_audit.py
PYTHONPATH=. python3 scripts/paranoia_audit.py
```

Regenerate datasets and ground truth:

```bash
PYTHONPATH=. python3 scripts/sync_repo.py
PYTHONPATH=. python3 scripts/sync_repo.py --refresh-eyes   # refresh Eyes corpus from GitHub
```

---

## Architecture

```
                    ┌─────────────────────────────┐
                    │  web/constraints-dash       │
                    │  (HTML puzzle solver UI)    │
                    └──────────────┬──────────────┘
                                   │ JSON API
                    ┌──────────────▼──────────────┐
                    │  cipherops/constraints/     │
                    │  propagate → validate → loop│
                    └──────────────┬──────────────┘
           ┌───────────────────────┼───────────────────────┐
           ▼                       ▼                       ▼
   cipherops/ciphers/      cipherops/analysis/     datasets/
   (77 variants)           (fingerprint, Kasiski)   fingerprinted + unsolved
```

| Layer | Role |
|-------|------|
| **`web/constraints-dash/`** | Primary interface — paste cipher, run toolset, browse findings, apply cribs |
| **`cipherops/constraints/`** | Shared-keystream (Noita depth), autokey stream extension, GAK dynamic perm |
| **`cipherops/ciphers/`** | Encrypt/decrypt implementations with math audit |
| **`cipherops/analysis/`** | Ciphertext profiling and attack-viability metadata |
| **`datasets/`** | Fingerprinted roundtrips (regression), unsolved corpora (Noita), property profiles |
| **`scripts/`** | Dataset generation, validation, corpus import, dash server |

Constraint propagation docs: [`docs/cryptanalysis/constraint-propagation.md`](docs/cryptanalysis/constraint-propagation.md).  
Noita model: [`docs/math-formulas/noita-eye.md`](docs/math-formulas/noita-eye.md).

---

## Project structure

```
h3x-cipherops/
├── web/constraints-dash/       # HTML/CSS/JS puzzle solver UI
├── cipherops/
│   ├── ciphers/                # Classical & modern cipher implementations
│   ├── constraints/            # Propagators, validation loop, crib hints
│   ├── analysis/               # Profiling (fingerprint, Kasiski, attacks)
│   └── cli.py                  # Headless CLI
├── datasets/
│   ├── fingerprinted/          # Roundtrip-verified cipher samples (regression)
│   ├── constraint-findings/    # Audited propagation outputs (oracle, not training)
│   ├── ciphertext-properties/  # Statistical profiles per record
│   └── unsolved/               # Noita eye messages (primary puzzle)
├── docs/math-formulas/         # Math definitions per cipher family
├── docs/cryptanalysis/         # Methods, taxonomy, constraint propagation
└── scripts/
    ├── serve_constraints_dash.py
    ├── generate_constraint_findings.py
    ├── import_eyes_corpus.py
    ├── sync_repo.py
    └── … validation & audit suite
```

---

## Datasets (supporting the solver, not the product)

| Corpus | Path | Purpose |
|--------|------|---------|
| Fingerprinted ciphers | `datasets/fingerprinted/` | Prove implementations; demo known families in the UI |
| Noita eye messages | `datasets/unsolved/noita-eye-messages/` | Primary unsolved puzzle (9 messages, deck size 83) |
| Constraint findings | `datasets/constraint-findings/` | Reproducible propagation audit trail |
| Ciphertext properties | `datasets/ciphertext-properties/` | Precomputed stats for fingerprinted records |

Math docs: [`docs/math-formulas/`](docs/math-formulas/). Cryptanalysis reference: [`docs/cryptanalysis/`](docs/cryptanalysis/).

---

## Roadmap (solver-first)

- [x] Validated cipher implementations (77 variants) + math audit
- [x] Constraint propagators (shared keystream, autokey, GAK)
- [x] Validated findings loop with graceful stop + suggestions
- [x] HTML dashboard — paste cipher, run toolset, crib auto-fill from findings
- [x] Noita corpus import and depth propagation
- [x] **Family identification** in the UI — fingerprint → suggested propagator / decoder (classification panel)
- [ ] **Unified attack lane** — route pasted input to decrypt, brute, or propagate automatically
- [ ] **Noita solver session** — partial keystream map, column coverage, crib-drag helpers
- [ ] **Crib-drag engine** — try word lists at offsets across all nine messages
- [ ] Runnable attack execution (beyond schema/heuristics)
- [ ] Optional LLM hypothesis proposer (engine remains source of truth)

Legacy / optional: LoRA fine-tuning scripts and Pre-LLM ingestion remain in the repo but are not the primary direction.

---

## Contributing

Open an issue or PR — label it `solver`, `cipherops`, or `docs`.

---

## License

MIT © Null-H3x — see `LICENSE`.
