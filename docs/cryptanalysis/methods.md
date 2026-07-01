# Cryptanalysis Methods

Statistical and structural techniques for classical ciphertext. All formulas match the implementation in `cipherops/analysis/`.

**Primary references:** William F. Friedman (Index of Coincidence, ~1920s); Friedrich Kasiski (1863); standard treatments in [Wikipedia: Index of coincidence](https://en.wikipedia.org/wiki/Index_of_coincidence), [Kasiski examination](https://en.wikipedia.org/wiki/Kasiski_examination).

---

## Index of Coincidence (IC)

Measures how often two randomly chosen symbols from a text are identical. Language text has higher IC than uniform random text.

For text of length \(n\), symbol counts \(n_i\):

\[
\text{IC} = \frac{\sum_i n_i(n_i - 1)}{n(n-1)}
\]

**English (26 letters):** IC ≈ **0.067**  
**Random monoalphabetic (mod 26):** IC ≈ **0.038** (= 1/26)

Implemented: `cipherops.analysis.fingerprint.index_of_coincidence`

---

## Friedman key-length estimate

Estimates repeating-key length for polyalphabetic ciphers from global IC (Friedman / coincidence attack).

\[
\hat{m} = \frac{0.027 \cdot n}{(n-1) \cdot \text{IC} - 0.038n + 0.065}
\]

Where \(n\) = alphabetic length, IC = ciphertext IC. Requires \(n \gtrsim 20\).

**Interpretation:** Values near integers suggest Vigenère/Gronsfeld period. Confirm with coset IC (below).

Implemented: `cipherops.analysis.fingerprint.friedman_key_length_estimate`

Cross-validated against: [LeandroSQ/vigenere-solver](https://github.com/LeandroSQ/vigenere-solver), [bbzaffari/VigenereDecryptor](https://github.com/bbzaffari/VigenereDecryptor) (Friedman + IC workflow).

---

## Kasiski examination

Finds repeated ciphertext substrings; distances between repeats are often multiples of the key length.

**Algorithm (implemented in `cipherops/analysis/kasiski.py`):**

1. Scan n-grams for \(n \in \{3,4,5\}\)
2. Record positions of each repeated n-gram
3. Collect spacings \(\Delta = pos_2 - pos_1\)
4. GCD of spacings → candidate periods
5. Score divisors 2..max_period by how often they divide spacings

**Output fields:** `repeats_found`, `repeat_spacings`, `spacing_gcd`, `candidate_key_lengths`, `strongest_period`

Cross-validated against: [ichantzaras/polysub-cryptanalysis](https://github.com/ichantzaras/polysub-cryptanalysis) (`kasiski.py` module).

---

## Coset IC (column / Friedman confirmation)

After hypothesizing period \(m\), split ciphertext into \(m\) cosets (every \(m\)-th character starting at offsets \(0..m-1\)). Compute IC of each coset; average IC should rise toward English (~0.067) when \(m\) is correct.

\[
\text{IC}_j = \text{IC}(\{c_i : i \equiv j \pmod m\})
\]

**Rule of thumb:** Correct period maximizes mean coset IC vs wrong periods.

Implemented: `cipherops/analysis/coset_ic.py`  
Stored in property profiles under `coset_ic`.

Cross-validated against: [RohitPatidar123-hub/classical-cryptanalysis-vigenere](https://github.com/RohitPatidar123-hub/classical-cryptanalysis-vigenere) (IC per group confirms key length).

---

## Mutual Index of Coincidence (MIC)

For each coset at the correct period, try all 26 Caesar shifts; score alignment with English using MIC or χ². Recovers key characters one column at a time.

**Not yet implemented** as executable attack — documented for future crib/key recovery. Reference: RohitPatidar123-hub (MIC analysis step).

---

## Chi-squared (χ²) vs English

\[
\chi^2 = \sum_{c \in A} \frac{(O_c - E_c)^2}{E_c}
\]

\(O_c\) = observed count, \(E_c\) = expected count from English unigram frequencies (`ENGLISH_FREQ` in `fingerprint.py`).

Lower χ² → better language fit. Used for scoring decryption candidates.

Implemented: `cipherops.analysis.fingerprint.chi_squared_english`

---

## Shannon entropy

\[
H = -\sum_x p(x) \log_2 p(x)
\]

Bits per symbol. Uniform random over \(k\) symbols: \(H = \log_2 k\).

Implemented: `cipherops.analysis.fingerprint.shannon_entropy`

---

## Attack workflow (polyalphabetic)

```
Ciphertext
    → Global IC / entropy        (mono vs poly vs random?)
    → Kasiski + Friedman         (candidate period m)
    → Coset IC at each m         (confirm period)
    → MIC / χ² per coset         (recover key shifts)  [future]
    → Decrypt
```

For **transposition**: IC preserved (~English) but n-grams broken; anagram/dictionary scoring instead.

For **homophonic**: IC preserved, flat symbol distribution; homophone count analysis.

---

## Property profile fields

See [`../variable-inventory.md`](../variable-inventory.md) §5 for `fingerprint`, `kasiski`, `coset_ic`, `frequency`, `ngrams`, `patterns`, `attacks`.
