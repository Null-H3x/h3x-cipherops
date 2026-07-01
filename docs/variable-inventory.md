# Variable Inventory

Complete reference of symbols, fields, and parameters tracked across LLM-Cryptography — from mathematical notation through datasets, property profiles, and ground truth.

**Scope:** 47 solved cipher variants (470 fingerprinted records) + 1 unsolved corpus (9 Noita eye messages) + 479 ciphertext property profiles.

---

## How the layers connect

```
docs/math-formulas/          Mathematical symbols (P, C, K, IC, …)
        ↓
cipherops/ciphers/registry   Implementation + params per variant
        ↓
datasets/fingerprinted/      Plaintext/ciphertext pairs (solved)
datasets/unsolved/           Ciphertext-only corpora
        ↓
datasets/ciphertext-properties/   Fingerprint, frequency, Kasiski, coset IC, attacks
docs/cryptanalysis/               Grounded cryptanalysis reference (methods, keyspace, isomorphs)
        ↓
Pre-LLM-Ingestion/processed/      Audited ground-truth registry
```

Each record links upward via `math_ref`, sideways via `id`, and downward via `properties_path`.

---

## 1. Mathematical notation

Defined in [`docs/math-formulas/definitions.md`](math-formulas/definitions.md).

### Universal cipher variables

| Symbol | Meaning | Domain |
|--------|---------|--------|
| **P** | Plaintext | 𝒫 |
| **C** | Ciphertext | 𝒞 |
| **K** | Key | 𝒦 |
| **E** | Encryption function | E_K: 𝒫 → 𝒞 |
| **D** | Decryption function | D_K: 𝒞 → 𝒫 |

### Character and alphabet

| Symbol | Meaning | Notes |
|--------|---------|-------|
| **x**, **i**, **j** | Character index / position | 0-based |
| **α** | Alphabet size | Usually 26 |
| **A** | Alphabet set | Ordered characters |
| **N** | Message length | \|P\| or \|C\| |

### Key material

| Symbol | Meaning | Used by |
|--------|---------|---------|
| **k**, **K** | Shift / key value | Caesar, Affine |
| **s** | Substitution mapping | Simple substitution |
| **v** | Key vector (length m) | Vigenère, Autokey, Beaufort |
| **a**, **b** | Affine coefficients | Affine (gcd(a,26)=1) |
| **M** | Polybius / Playfair square | Polybius, Playfair |
| **H** | Hill matrix (n×n) | Hill cipher |

### Statistical / analysis

| Symbol | Meaning | Formula |
|--------|---------|---------|
| **IC** | Index of coincidence | Σ n_i(n_i−1) / n(n−1) |
| **H** | Shannon entropy | −Σ p(x) log₂ p(x) |
| **χ²** | Chi-squared vs English | Frequency deviation test |

### Noita eye corpus (unsolved)

| Symbol | Meaning | Value |
|--------|---------|-------|
| **N** | Deck size | 83 (symbols 0..82) |
| **K[t]** | Position-indexed keystream | Hypothesized shared across messages |
| **P_i[t]**, **C_i[t]** | Plaintext/ciphertext at position t in message i | Plaintext unknown |

---

## 2. Cipher registry (`CipherSpec`)

Source: `cipherops/ciphers/registry.py` — **47 variants**.

| Field | Type | Description |
|-------|------|-------------|
| `family` | string | Logical cipher family (e.g. `vigenere`, `aes_gcm`) |
| `slug` | string | Unique variant id (e.g. `vigenere-keyword`) |
| `params` | object | Fixed key/material for dataset generation (see §7) |
| `math_ref` | string | Path to formula doc |
| `difficulty` | int (1–7) | Cryptanalytic difficulty rating |
| `variants` | string[] | Sub-variant tags (e.g. `standard`, `beaufort`) |
| `encrypt_only` | bool | True for hashes and lossy fractionated-morse |
| `era` | string | `classical` \| `modern` |

---

## 3. Fingerprinted dataset records

Path: `datasets/fingerprinted/{slug}/data.jsonl` — **470 records** (10 × 47 ciphers).

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | `{slug}-{01..10}` |
| `plaintext` | string | One of 10 canonical `PLAIN_SAMPLES` |
| `ciphertext` | string | Encrypted output |
| `cipher_family` | string | Matches registry `family` |
| `params` | object | Variant parameters (see §7) |
| `math_ref` | string | Formula documentation path |
| `era` | string | `classical` or `modern` |
| `difficulty` | int | 1–7 |
| `variants` | string[] | Optional; present when registry defines sub-variants |
| `validation.plaintext_sha256` | hex | SHA-256 of plaintext |
| `validation.roundtrip_verified` | bool | Decrypt(Encrypt(P)) ≈ P |
| `validation.encrypt_only` | bool | One-way or lossy encrypt |

### Canonical plaintext corpus (`PLAIN_SAMPLES`)

Ten fixed English sentences shared identically across all 47 fingerprinted variants — ensures cross-cipher comparability.

---

## 4. Unsolved dataset records

Path: `datasets/unsolved/noita-eye-messages/data.jsonl` — **9 records**.

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | `noita-eye-messages-{east\|west}-{n}` |
| `plaintext` | null | Unknown |
| `ciphertext` | int[] | Symbol stream, each value in [0, 82] |
| `cipher_family` | string | `noita-eye` |
| `params.deck_size` | int | 83 |
| `params.label` | string | e.g. `East 1`, `West 3` |
| `params.message_index` | int | 0–8 |
| `params.alphabet` | string | `integer-mod-83` |
| `params.hypothesis` | string | `polyalphabetic_shared_keystream` |
| `math_ref` | string | `docs/math-formulas/noita-eye.md` |
| `era` | string | `unsolved` |
| `difficulty` | null | — |
| `validation.plaintext_sha256` | null | — |
| `validation.ciphertext_sha256` | hex | Hash of integer array |
| `validation.roundtrip_verified` | false | — |
| `validation.encrypt_only` | false | — |
| `validation.status` | string | `unsolved` |
| `validation.symbol_range_ok` | bool | All symbols in deck |
| `validation.length` | int | Message symbol count |
| `source.repository` | URL | Null-H3x/Eyes |
| `source.corpus_path` | string | `noita_eye_core/corpus.json` |
| `source.origin` | URL | noita-eyes.neocities.org |
| `metadata.header_anomaly.index_1` | int | 66 (universal across all 9 messages) |
| `metadata.header_anomaly.index_2` | int | 5 (universal across all 9 messages) |
| `metadata.sigma0_ct_target` | int | Per-message σ₀ target |

### Bundled corpus (`corpus.json`)

| Field | Description |
|-------|-------------|
| `deck_size` | 83 |
| `num_messages` | 9 |
| `message_labels` | East/West pair labels + East 5 |
| `message_lengths` | Per-message symbol counts (1036 total) |
| `ciphertexts` | Full integer arrays |
| `sigma0_ct_targets` | Nine target values |

---

## 5. Ciphertext property records

Path: `datasets/ciphertext-properties/{slug}/properties.jsonl` — **479 records** (470 solved + 9 unsolved).

Each row mirrors a fingerprinted or unsolved record by `id` and adds cryptanalytic metadata from `cipherops/analysis/`.

### `source` — linkage

| Field | Description |
|-------|-------------|
| `fingerprinted_path` | Source JSONL path |
| `cipher_family` | — |
| `variant_slug` | — |
| `ciphertext_sha256` | Integrity hash of ciphertext |
| `status` | `solved` \| `unsolved` |

### `stream` — normalized analysis input

| Field | Description |
|-------|-------------|
| `raw_length` | Original ciphertext character count |
| `analysis_text_length` | Length after normalization |
| `symbol_class` | `alpha` \| `hex` \| `base64` \| `integer` \| `printable` |
| `alphabet_size` | Effective symbol space size |

### `fingerprint` — statistical fingerprinting

| Field | Maps to | Description |
|-------|---------|-------------|
| `shannon_entropy_bits` | **H** | Bits per symbol |
| `index_of_coincidence` | **IC** | Coincidence index |
| `normalized_ic_ratio` | — | (IC − random) / (language − random) |
| `chi_squared_english` | **χ²** | English frequency fit (alpha streams) |
| `friedman_key_length_estimate` | — | Estimated Vigenère period |
| `language_ic_reference` | — | Baseline IC (~0.067 English) |
| `random_ic_reference` | — | Flat-alphabet baseline (~0.038 mod 26) |
| `unique_symbols` | — | Distinct symbol count |
| `symbol_class` | — | Same as stream |

### `frequency` — unigram analysis

| Field | Description |
|-------|-------------|
| `unigram` | `{symbol: proportion}` full distribution |
| `top_unigrams` | `[[symbol, freq], …]` ranked top 10 |
| `total_symbols` | Symbol count in analysis stream |

### `kasiski` — periodicity / Kasiski examination

| Field | Description |
|-------|-------------|
| `repeats_found` | Count of repeated n-grams |
| `repeat_spacings` | Distances between repeat occurrences |
| `spacing_gcd` | GCD of spacings |
| `candidate_key_lengths` | Likely key periods |
| `strongest_period` | Highest-confidence period |

### `coset_ic` — column-wise IC for period confirmation

Present when `stream.symbol_class == "alpha"`. Computes mean index of coincidence across cosets at each candidate period (2–20). See [`docs/cryptanalysis/methods.md`](cryptanalysis/methods.md).

| Field | Description |
|-------|-------------|
| `periods_tested` | Number of periods evaluated |
| `best_period` | Period with highest mean coset IC |
| `best_mean_ic` | Mean IC at `best_period` |
| `english_ic_reference` | English baseline (~0.067) |
| `by_period` | `{period: mean_ic}` map (string keys) |

### `ngrams` — n-gram structure

| Field | Description |
|-------|-------------|
| `bigram_top` | Top bigrams with relative frequency |
| `trigram_top` | Top trigrams with relative frequency |
| `bigram_count` | Total bigram positions |
| `trigram_count` | Total trigram positions |

### `patterns` — word and structural features

| Field | Description |
|-------|-------------|
| `preserves_spaces` | Spaces survive encryption |
| `preserves_punctuation` | Punctuation survives encryption |
| `word_boundary_markers` | Detected delimiters (e.g. `[" "]`) |
| `estimated_words` | Word count estimate (when spaces preserved) |
| `avg_token_length` | Mean token length |
| `token_length_histogram` | `{length: count}` |
| `repeated_blocks` | `[{block, count}]` recurring substrings |

### `attacks` — attack-surface metadata (6 vectors)

Each vector (`crib_dragging`, `brute_force`, `dictionary`, `hill_climbing`, `metaheuristic`, `side_channel`) contains:

| Field | Description |
|-------|-------------|
| `viable` | `viable` \| `partial` \| `not_viable` \| `not_applicable` \| `unknown` |
| `confidence` | Heuristic score 0.0–1.0 |
| `notes` | Human-readable rationale |
| `key_space_estimate` | Optional search-space description |
| `recommended_methods` | Applicable technique names |

These slots reserve structure for future crib-drag, brute-force, dictionary, hill-climbing, metaheuristic, and side-channel tooling without requiring those tools to exist yet.

### `validation` — reproducibility

| Field | Description |
|-------|-------------|
| `properties_sha256` | Hash of all computed properties (excludes id/source/validation) |
| `analyzer_version` | Schema version (currently `1.1.0`) |

---

## 6. Ground truth registry

Path: `Pre-LLM-Ingestion/processed/cipher-ground-truth.jsonl` — **48 records**.

| Field | Description |
|-------|-------------|
| `cipher_family` | Registry family |
| `variant_slug` | Registry slug |
| `params` | Fixed parameters |
| `math_ref` | Formula doc |
| `difficulty` | int or null (unsolved) |
| `variants` | Sub-variant list |
| `dataset_path` | Plaintext/ciphertext JSONL |
| `properties_path` | Ciphertext properties JSONL |
| `audit_status` | `math_implementation_verified` \| `unsolved_corpus_imported` |
| `status` | `solved` \| `unsolved` |
| `source_repo` | External repo URL (unsolved only) |

### Q&A ground truth (`cipher-qna-ground-truth.jsonl`)

Additional fields for instruction tuning:

| Field | Description |
|-------|-------------|
| `instruction` | Prompt |
| `input` | Context (often empty) |
| `output` | Expected response |
| `math_ref` | Linked formula doc |
| `cipher_family` | — |
| `status` | Present on unsolved rows |

---

## 7. Cipher-specific `params` keys

Parameters stored on every dataset record and ground-truth row.

| Family / slug pattern | Param keys |
|-----------------------|------------|
| Caesar (`caesar-rot3`, `caesar-rot13`) | `shift` |
| Affine | `a`, `b` |
| Rail fence | `rails` |
| Baconian | `a_char`, `b_char` |
| Polybius | `key` |
| Substitution | `mapping` |
| Nomenclator | `codebook` |
| Columnar | `key` |
| Autokey | `key`, `variant` |
| Beaufort, Porta, Vigenère, Playfair, Bifid, Trifid | `key` |
| Running key | `key_source` |
| Gronsfeld | `numeric_key` |
| Homophonic | `mapping` |
| Four-square | `key1`, `key2` |
| Hill | `matrix` |
| ADFGX / ADFGVX | `polybius_key`, `transposition_key` |
| Straddle checkerboard | `layout` |
| Fractionated Morse | `substitution_key` |
| Base64 | _(empty)_ |
| AES-GCM / AES-CBC / AES-CTR | `key_bits`, `mode` |
| ChaCha20-Poly1305 | `key_bits` |
| Triple DES | `key_bits`, `mode` |
| Fernet | `construction` |
| XOR-SHA256 stream | `keystream` |
| PBKDF2-AES-GCM | `kdf`, `iterations` |
| HKDF-AES-GCM | `kdf` |
| RSA-OAEP hybrid | `padding`, `hybrid` |
| Ed25519 sign | `curve` |
| X25519 ECDH | `curve` |
| SHA-256 / SHA-512 / SHA3-256 / BLAKE2b | `output_bits` |
| HMAC-SHA256 | `hash` |
| Noita eye messages | `deck_size`, `label`, `message_index`, `alphabet`, `hypothesis` |

---

## 8. Manifest index fields

### `datasets/fingerprinted/manifest.json`

| Field | Description |
|-------|-------------|
| `slug` | Variant id |
| `count` | Records per variant (10) |
| `path` | JSONL path |

### `datasets/unsolved/manifest.json`

| Field | Description |
|-------|-------------|
| `slug` | Corpus id |
| `count` | Record count (9) |
| `path` | JSONL path |
| `status` | `unsolved` |
| `source_repo` | Eyes repository URL |
| `math_ref` | Formula doc |

### `datasets/ciphertext-properties/manifest.json`

| Field | Description |
|-------|-------------|
| `slug` | Variant or corpus id |
| `count` | Property record count |
| `path` | properties.jsonl path |
| `corpus_type` | `fingerprinted` \| `unsolved` |
| `source_path` | Upstream JSONL path |

---

## 9. Coverage summary

| Layer | Records | Primary variables |
|-------|---------|-----------------|
| Math notation | 47 formula docs | P, C, K, E, D, IC, H, family-specific keys |
| Cipher registry | 47 variants | family, slug, params, era, encrypt_only |
| Fingerprinted datasets | 470 | plaintext, ciphertext, validation hashes |
| Unsolved datasets | 9 | integer ciphertext, header anomaly, σ₀ targets |
| Ciphertext properties | 479 | fingerprint, frequency, kasiski, coset_ic, ngrams, patterns, attacks |
| Ground truth | 48 | cross-links math ↔ data ↔ properties |

---

## 10. Not yet stored (reserved for future tooling)

The following are **not** persisted as dataset fields today but have reserved attack-vector slots and documented extension points:

| Future variable | Reserved in |
|-----------------|-------------|
| Crib text / positions | `attacks.crib_dragging` |
| Dictionary / wordlist scores | `attacks.dictionary` |
| Brute-force key candidates | `attacks.brute_force.key_space_estimate` |
| Hill-climb state / fitness | `attacks.hill_climbing` |
| GA/SA/PSO run parameters | `attacks.metaheuristic.recommended_methods` |
| Timing / power / cache traces | `attacks.side_channel` |
| Recovered keystream (Noita) | Future unsolved update when plaintext known |

---

## Regenerate and validate

```bash
pip install -r requirements-validate.txt
PYTHONPATH=. python3 scripts/sync_repo.py
PYTHONPATH=. python3 scripts/comprehensive_validate.py --deep
```

See also: [`datasets/ciphertext-properties/README.md`](../datasets/ciphertext-properties/README.md), [`Pre-LLM-Ingestion/README.md`](../Pre-LLM-Ingestion/README.md).
