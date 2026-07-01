# Ciphertext Properties Dataset

Cryptanalytic metadata computed for every record in the fingerprinted and unsolved corpora. Each `properties.jsonl` row links to its source ciphertext by `id` and includes measurable features plus attack-surface hints for downstream LLM training and CipherOps tooling.

## Layout

```
datasets/ciphertext-properties/
├── manifest.json
├── {variant-slug}/
│   └── properties.jsonl
└── README.md
```

## Record Schema

| Section | Fields | Purpose |
|---------|--------|---------|
| `source` | `fingerprinted_path`, `cipher_family`, `variant_slug`, `ciphertext_sha256`, `status` | Link back to plaintext/ciphertext corpus |
| `stream` | `raw_length`, `analysis_text_length`, `symbol_class`, `alphabet_size` | Normalized analysis stream (alpha, hex, base64, integer, printable) |
| `fingerprint` | Shannon entropy, IC, normalized IC ratio, chi-squared vs English, Friedman estimate | Classical fingerprinting |
| `frequency` | `unigram`, `top_unigrams` | Symbol frequency profile |
| `kasiski` | repeat spacings, GCD, candidate key lengths | Periodicity / Kasiski examination |
| `ngrams` | top bigrams/trigrams | N-gram structure |
| `patterns` | spaces, punctuation, word estimates, repeated blocks | Word/structural patterns |
| `attacks` | six vectors (see below) | Attack viability metadata with confidence and recommended methods |
| `validation` | `properties_sha256`, `analyzer_version` | Reproducibility |

### Attack vectors (`attacks.*`)

Each vector includes:

- `viable`: `viable` | `partial` | `not_viable` | `not_applicable` | `unknown`
- `confidence`: 0.0–1.0 heuristic confidence
- `notes`: human-readable rationale
- `key_space_estimate`: optional search-space hint
- `recommended_methods`: list of applicable techniques

Vectors:

1. **crib_dragging** — known-plaintext / cross-message cribs
2. **brute_force** — exhaustive key search
3. **dictionary** — wordlist / language scoring
4. **hill_climbing** — local search on key/substitution state
5. **metaheuristic** — GA, SA, PSO, tabu, etc.
6. **side_channel** — timing, power, cache, fault (implementation-focused)

## Regenerate

```bash
PYTHONPATH=. python3 scripts/generate_ciphertext_properties.py
PYTHONPATH=. python3 scripts/validate_ciphertext_properties.py
```

Implementation: `cipherops/analysis/`. Schema version: `analyzer_version` in each record (currently `1.0.0`).
