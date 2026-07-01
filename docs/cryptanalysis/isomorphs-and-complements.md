# Isomorphs and Complement Patterns

Structural relationships in ciphertext that reduce search space or identify cipher class.

---

## Complement / reciprocal ciphers

Ciphers where encryption equals decryption (self-reciprocal) or map each letter to a fixed complement.

| Cipher | Map | Property |
|--------|-----|----------|
| **Atbash** | \(x \mapsto 25 - x\) | Involution: \(E(E(x)) = x\) |
| **ROT13** | \(x \mapsto x + 13\) | Involution mod 26 |
| **Beaufort** | \(x \mapsto k - x\) | Self-reciprocal for fixed key |
| **Porta** | Half-alphabet swap | Self-reciprocal per key letter |

**Detection:** Try complement/ROT13/Beaufort on sample; IC unchanged under monoalphabetic complement.

**Implementation:** `classical.atbash`, `classical.beaufort`; verified in `scripts/math_audit.py` (Beaufort involution KAT).

---

## Caesar isomorph class

All Caesar shifts produce the same **bigram/trigram structure** shifted cyclically; IC identical. Key recovery is unique up to 25 choices — smallest brute-force space among polyalphabetic families.

---

## Affine equivalence

Valid keys \((a,b)\) with \(\gcd(a,26)=1\). Only **12** choices for \(a\); each defines a multiplicative permutation; \(b\) shifts. Total 312 keys — brute-force feasible.

---

## Isomorphs (structural repetition)

**Definition** (from [NBiermann/cryptohelper-isomorphs](https://github.com/NBiermann/cryptohelper-isomorphs)):

> Fragments in the ciphertext whose **internal structure** is exactly repeated: if two positions in sequence A hold the same symbol, the corresponding positions in sequence B do as well (and vice versa).

**Example** (from George Lasry's Friedman-ring challenge):

```
...wqiqswazzrq...
...pasatpybbqa...
   12 2 1 33 2
```

Same relative-equality pattern → isomorphic substrings. Used to constrain ciphertext alphabet for disk ciphers (Wheatstone) and complex historical systems.

**Significance** (NBiermann):  
\(\text{significance} = [\text{# repeated positions}] - [\text{# distinct repeated symbols}]\)

**References:**
- [Lasry, *Cryptologia* 2021 — French cipher analysis](https://www.tandfonline.com/doi/full/10.1080/01611194.2021.1996484)
- [Friedman ring challenge](https://scienceblogs.de/klausis-krypto-kolumne/the-friedman-ring-challenge-by-george-lasry/)

**Status in this repo:** Documented; detection not yet in `cipherops/analysis/` (future `isomorphs.py`). Property `patterns.repeated_blocks` captures simpler exact repeats.

---

## Depth / in-depth messages (Noita eye)

When ciphertext at absolute position \(t\) is identical across messages, under shared keystream \(K[t]\):

\[
C_i[t] - C_j[t] \equiv P_i[t] - P_j[t] \pmod{83}
\]

Keystream cancels — **plaintext difference structure** is observable without knowing \(K\). This is the "in depth" / multi-ciphertext Vigenère property documented in [`../math-formulas/noita-eye.md`](../math-formulas/noita-eye.md) and the [Eyes](https://github.com/Null-H3x/Eyes) `noita_eye_core/depth` module.

---

## Homophonic isomorphs

Multiple ciphertext symbols per plaintext letter preserve **plaintext bigram statistics** in aggregate but flatten unigram IC. Zodiac 408 / Copiale-style ciphers require homophonic scoring, not simple substitution IC.

**Reference:** [matthewdgreen/decipher](https://github.com/matthewdgreen/decipher) homophonic anneal path.

**Status:** Not implemented; listed in `cipher-families.md` (Copiale reference-only).

---

## Transposition isomorphs

Same multiset of characters; different order. IC ≈ English; **n-gram** and **word boundary** patterns break. Anagram search space vs substitution search space.

---

## Summary table

| Pattern | IC effect | Primary attack |
|---------|-----------|----------------|
| Complement (Atbash/ROT13) | Unchanged | 1–25 key trials |
| Isomorph substrings | Local structure | Alphabet reduction |
| In-depth alignment | Difference cancels key | Crib-drag, N-way depth |
| Homophonic flattening | High IC, flat unigrams | Homophone scoring |
| Transposition | High IC, broken n-grams | Anagram / route search |
