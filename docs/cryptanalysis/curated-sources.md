# Curated External Sources

GitHub repositories and references reviewed for **ground-truth alignment** with this project's math and analysis. We cite these for methodology; implementations here are independent unless noted.

---

## Credits & acknowledgements

The following people and projects informed the cryptanalysis reference docs and analyzer design. Thank you for publishing open, verifiable work.

| Author | Repository / work | Contribution to this repo |
|--------|-------------------|---------------------------|
| **[@ichantzaras](https://github.com/ichantzaras)** | [polysub-cryptanalysis](https://github.com/ichantzaras/polysub-cryptanalysis) | Kasiski module structure; IC + frequency workflow for Vigenère ([`methods.md`](methods.md)) |
| **[@LeandroSQ](https://github.com/LeandroSQ)** | [vigenere-solver](https://github.com/LeandroSQ/vigenere-solver) (MIT) | Friedman test + IC + χ² pipeline ([`methods.md`](methods.md)) |
| **[@bbzaffari](https://github.com/bbzaffari)** | [VigenereDecryptor](https://github.com/bbzaffari/VigenereDecryptor) | Kasiski + IC + χ² (IEEE report) ([`methods.md`](methods.md)) |
| **[@RohitPatidar123-hub](https://github.com/RohitPatidar123-hub)** | [classical-cryptanalysis-vigenere](https://github.com/RohitPatidar123-hub/classical-cryptanalysis-vigenere) | Coset IC, MIC concept, Kasiski GCD ([`methods.md`](methods.md)) |
| **[@DominicBreuker](https://github.com/DominicBreuker)** | [cryptanalysis](https://github.com/DominicBreuker/cryptanalysis) | Caesar 26-key search, Vigenère IoC period, substitution hill-climb |
| **[@NBiermann](https://github.com/NBiermann)** | [cryptohelper-isomorphs](https://github.com/NBiermann/cryptohelper-isomorphs) | Isomorph definition, pattern significance, sliding-window algorithm ([`isomorphs-and-complements.md`](isomorphs-and-complements.md)) |
| **[@matthewdgreen](https://github.com/matthewdgreen)** | [decipher](https://github.com/matthewdgreen/decipher) | Automated solver taxonomy: monoalphabetic, homophonic, periodic polyalphabetic, transposition+homophonic ([`isomorphs-and-complements.md`](isomorphs-and-complements.md)) |
| **[@systemslibrarian](https://github.com/systemslibrarian)** | [cipher-detective-ai](https://github.com/systemslibrarian/cipher-detective-ai) | 81-type cipher taxonomy for gap analysis |
| **[@Null-H3x](https://github.com/Null-H3x)** | [Eyes](https://github.com/Null-H3x/Eyes) | Noita eye corpus, GAK/xGAK kernel definitions (`eyestat_kernels.py`), depth attack (`datasets/unsolved/noita-eye-messages/`) |
| **George Lasry** | [Friedman ring challenge](https://scienceblogs.de/klausis-krypto-kolumne/the-friedman-ring-challenge-by-george-lasry/) · [Cryptologia 2021](https://www.tandfonline.com/doi/full/10.1080/01611194.2021.1996484) | Isomorph-driven alphabet reduction example ([`isomorphs-and-complements.md`](isomorphs-and-complements.md)) |

**Reviewed but not imported** (different problem domain; still credited for transparency):

| Author | Repository | Reason |
|--------|------------|--------|
| **[@SebassCoates](https://github.com/SebassCoates)** | [Isomorph](https://github.com/SebassCoates/Isomorph) | Graph-theory encryption scheme, not classical isomorph detection |
| **[@DanielProg39](https://github.com/DanielProg39)** | [Key-Space-Brute-Force](https://github.com/DanielProg39/Key-Space-Brute-Force) | Raw n-bit brute-force demo; not cipher-specific |

---

## Validated against (statistical methods)

| Source | Author | URL | What we cross-checked | License |
|--------|--------|-----|----------------------|---------|
| **polysub-cryptanalysis** | [@ichantzaras](https://github.com/ichantzaras) | [ichantzaras/polysub-cryptanalysis](https://github.com/ichantzaras/polysub-cryptanalysis) | Kasiski module structure, IC + frequency workflow for Vigenère | Check repo |
| **vigenere-solver** | [@LeandroSQ](https://github.com/LeandroSQ) | [LeandroSQ/vigenere-solver](https://github.com/LeandroSQ/vigenere-solver) | Friedman test + IC + χ² pipeline (MIT) | MIT |
| **VigenereDecryptor** | [@bbzaffari](https://github.com/bbzaffari) | [bbzaffari/VigenereDecryptor](https://github.com/bbzaffari/VigenereDecryptor) | Kasiski + IC + χ² (IEEE report) | Check repo |
| **classical-cryptanalysis-vigenere** | [@RohitPatidar123-hub](https://github.com/RohitPatidar123-hub) | [RohitPatidar123-hub/classical-cryptanalysis-vigenere](https://github.com/RohitPatidar123-hub/classical-cryptanalysis-vigenere) | Coset IC, MIC concept, Kasiski GCD | Check repo |
| **cryptanalysis** | [@DominicBreuker](https://github.com/DominicBreuker) | [DominicBreuker/cryptanalysis](https://github.com/DominicBreuker/cryptanalysis) | Caesar 26-key, Vigenère IoC period, substitution hill-climb | Check repo |

---

## Isomorphs & historical ciphers

| Source | Author | URL | What we document |
|--------|--------|-----|------------------|
| **cryptohelper-isomorphs** | [@NBiermann](https://github.com/NBiermann) | [NBiermann/cryptohelper-isomorphs](https://github.com/NBiermann/cryptohelper-isomorphs) | Isomorph definition, pattern significance, sliding-window algorithm |
| **decipher** | [@matthewdgreen](https://github.com/matthewdgreen) | [matthewdgreen/decipher](https://github.com/matthewdgreen/decipher) | Automated solver taxonomy: monoalphabetic, homophonic, periodic polyalphabetic, transposition+homophonic |
| **Lasry / Friedman ring** | George Lasry | [ScienceBlogs challenge](https://scienceblogs.de/klausis-krypto-kolumne/the-friedman-ring-challenge-by-george-lasry/) | Isomorph-driven alphabet reduction |
| **Eyes / Noita** | [@Null-H3x](https://github.com/Null-H3x) | [Null-H3x/Eyes](https://github.com/Null-H3x/Eyes) | In-depth keystream, depth attack, corpus (bundled in `datasets/unsolved/`) |

---

## Cipher taxonomy reference (not fully implemented)

| Source | Author | URL | Use |
|--------|--------|-----|-----|
| **cipher-detective-ai** | [@systemslibrarian](https://github.com/systemslibrarian) | [systemslibrarian/cipher-detective-ai](https://github.com/systemslibrarian/cipher-detective-ai) | 81-type taxonomy for gap analysis; educational heuristics only |
| **Practical Cryptography** | — | [practicalcryptography.com](https://www.practicalcryptography.com/cryptanalysis/) | Classical attack descriptions (web) |

---

## Academic / standards (modern ciphers in registry)

| Source | Use in repo |
|--------|-------------|
| [NIST SP 800-38A/B/D](https://csrc.nist.gov/publications/sp800) | AES modes (CBC, CTR, GCM) |
| [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) | HKDF |
| [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) | ChaCha20-Poly1305 |
| NIST SHA-256 empty-string KAT | `scripts/math_audit.py` |

---

## Wikipedia (formula verification)

| Article | Maps to |
|---------|---------|
| [Index of coincidence](https://en.wikipedia.org/wiki/Index_of_coincidence) | `fingerprint.index_of_coincidence` |
| [Kasiski examination](https://en.wikipedia.org/wiki/Kasiski_examination) | `kasiski.kasiski_examination` |
| [Frequency analysis](https://en.wikipedia.org/wiki/Frequency_analysis) | `frequency.frequency_profile` |

---

## Not imported (different problem domain)

| Source | Author | Reason |
|--------|--------|--------|
| [Isomorph](https://github.com/SebassCoates/Isomorph) | [@SebassCoates](https://github.com/SebassCoates) | Graph-theory encryption scheme, not classical isomorph detection |
| [Key-Space-Brute-Force](https://github.com/DanielProg39/Key-Space-Brute-Force) | [@DanielProg39](https://github.com/DanielProg39) | Raw n-bit brute force demo; not cipher-specific |

---

## How to extend this list

1. Verify formula or algorithm against our implementation (add KAT in `scripts/math_audit.py`)
2. Add row to this table with URL and validation note
3. Link from [`methods.md`](methods.md) or [`keyspace-reference.md`](keyspace-reference.md)
