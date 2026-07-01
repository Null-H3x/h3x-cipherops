# Unimplemented Ciphers — Reference Catalog

Ciphers and systems **named in taxonomies** or **common in puzzles / history** but **not yet** in `cipherops` registry. Formulas are reference-only unless noted.

**Implemented catalog:** 53 variants — see [`README.md`](README.md).  
**Encodings (PAM-5, etc.):** [`encodings-catalog.md`](encodings-catalog.md).  
**Gap priorities:** [`../cryptanalysis/taxonomy-gap-map.md`](../cryptanalysis/taxonomy-gap-map.md).

---

## Status legend

| Status | Meaning |
|--------|---------|
| **P1** | High value; moderate implementation effort |
| **P2** | Historical / niche |
| **P3** | Extended taxonomy; low immediate priority |
| **Corpus** | Import external ciphertext like Noita |

---

## Classical substitution & symbols

| Cipher | Type | Formula / model | Status | Priority |
|--------|------|-----------------|--------|----------|
| **Pigpen** | Symbol grid | 26 letters → Masonic cell symbols | **Implemented** (`pigpen-standard`) | — |
| **Dancing men** | Symbol pictographs | Sherlock Holmes cipher; figure poses | Reference | P2 |
| **Tic-tac-toe cipher** | Symbol grid | 3×3 cell + dot notation | Reference | P2 |
| **Copiale** | Homophonic symbols | Arbitrary symbol → letter mapping | Reference | **Corpus** |
| **Arabic / Runic variants** | Script substitution | Same as monoalphabetic on other alphabets | Reference | P3 |
| **Keyboard shift** | QWERTY route | Physical key position map | Reference | P3 |

---

## Transposition & mechanical

| Cipher | Type | Formula / model | Status | Priority |
|--------|------|-----------------|--------|----------|
| **Scytale** | Cylinder transposition | Read every \(d\)th character on staff diameter \(d\) | **Implemented** (`scytale-d5`) | — |
| **Grille** | Hole template | Overlay reveals message cells | Reference | P2 |
| **Route cipher** | 2D route | Spiral / boustrophedon fill | Reference | P2 |
| **Generic route** | \(\pi: \{0..n-1\} \to \{0..n-1\}\) | Partially covered by rail/columnar | Reference | P3 |
| **Jefferson disk** | Rotating disks | 36 disks × 26 letters; align to key | Reference | P2 |
| **M-94** | Cylinder | US military strip cipher | Reference | P2 |

---

## Polyalphabetic & compound

| Cipher | Type | Formula / model | Status | Priority |
|--------|------|-----------------|--------|----------|
| **Nihilist** | Polybius + numeric key | \((r,c) + k_i \mod 10\) per digit pair | **Implemented** (`nihilist-31415`) | — |
| **VIC** | Multi-stage | Straddling checkerboard + chain addition + transposition | Reference | P2 |
| **Great cipher** | Louis XIV | Homophonic + nulls + traps | Reference | P2 |
| **Bazeries** | Cylinder + substitution | Dual disk system | Reference | P3 |
| **Ciphertext-autokey** | Autokey variant | \(k_i \leftarrow c_{i-\|K\|}\) after seed | Reference | P2 |
| **One-time pad (manual)** | Vernam | \(c_i = p_i \oplus k_i\), \(\|K\|=\|P\|\) | Reference | P3 |

---

## Rotor & machine ciphers

| Cipher | Type | Model | Status | Priority |
|--------|------|-------|--------|----------|
| **Enigma** | Rotor | Stepping rotors + reflector; permutation per key | Reference | P2 |
| **SIGABA** | Rotor | US ECM Mark II; 15 rotors | Reference | P3 |
| **Purple** | Machine | Japanese diplomatic; telephone stepping | Reference | P3 |
| **Lorenz SZ40** | Teleprinter XOR | Colossus target | Reference | P3 |
| **Hebern** | Rotor | Commercial predecessor to Enigma | Reference | P3 |

---

## Military & codeword

| Cipher | Type | Model | Status | Priority |
|--------|------|-------|--------|----------|
| **DRYAD** | XOR stream | US numeric strip + one-time pad | Reference | P2 |
| **Wahlwort** | Codeword book | German WWII word codes | Reference | P2 |
| **Book cipher** | Running key (book) | Page/line/word coordinates | Partial (`running-key-book`) | P2 |
| **ADFGX** (extended variants) | Fractionated | Multiple keyword stages | Partial (implemented base) | P3 |

---

## Modern / stego (reference)

| System | Type | Notes | Status |
|--------|------|-------|--------|
| **Null cipher** | Steganography | Message in nth letters | Reference |
| **Acrostic** | Steganography | Vertical read | Reference |
| **Visual crypto** | Secret sharing | XOR of images | Reference |
| **Copiale-style homophonic** | Manuscript | Needs homophone scorer | Corpus |

---

## Extended taxonomy (81-type gap samples)

From external classifier taxonomies — **not implemented**:

| Category | Examples |
|----------|----------|
| Non-Latin classical | Cyrillic Caesar, Japanese ciphers |
| Puzzle variants | Keyboard, phone keypad T9 |
| Historical compound | Alberti disk, Chappe telegraph codes |
| Modern pen-and-paper | Solitaire (Pontifex), Hand cipher by Bruce Schneier |

---

## Relationship to implemented families

| You need… | Use instead (today) |
|-----------|---------------------|
| Simple shift | Caesar / Atbash |
| Repeating key | Vigenère / Beaufort / Gronsfeld |
| Non-repeating key | Autokey / running key |
| Symbol substitution | Homophonic / nomenclator (partial) |
| Digraph | Playfair / four-square |
| Fractionation | ADFGX / bifid / trifid |
| Line encoding | **PAM-5**, Base64, Baconian, Hex, Manchester |
| Symbol substitution | **Pigpen** |
| Cylinder transposition | **Scytale** |
| Polybius + numeric key | **Nihilist** |

---

## Adding a cipher from this catalog

1. Math doc in `docs/math-formulas/<name>.md`
2. `cipherops/ciphers/` implementation + roundtrip
3. `CipherSpec` in `registry.py`
4. `PYTHONPATH=. python3 scripts/sync_repo.py`
5. Update this file status → **Implemented**
