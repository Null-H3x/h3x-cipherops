# Curated External Sources

GitHub repositories and references reviewed for **ground-truth alignment** with this project's math and analysis. We cite these for methodology; implementations here are independent unless noted.

---

## Validated against (statistical methods)

| Source | URL | What we cross-checked | License |
|--------|-----|----------------------|---------|
| **polysub-cryptanalysis** | [ichantzaras/polysub-cryptanalysis](https://github.com/ichantzaras/polysub-cryptanalysis) | Kasiski module structure, IC + frequency workflow for Vigenère | Check repo |
| **vigenere-solver** | [LeandroSQ/vigenere-solver](https://github.com/LeandroSQ/vigenere-solver) | Friedman test + IC + χ² pipeline (MIT) | MIT |
| **VigenereDecryptor** | [bbzaffari/VigenereDecryptor](https://github.com/bbzaffari/VigenereDecryptor) | Kasiski + IC + χ² (IEEE report) | Check repo |
| **classical-cryptanalysis-vigenere** | [RohitPatidar123-hub/classical-cryptanalysis-vigenere](https://github.com/RohitPatidar123-hub/classical-cryptanalysis-vigenere) | Coset IC, MIC concept, Kasiski GCD | Check repo |
| **cryptanalysis** | [DominicBreuker/cryptanalysis](https://github.com/DominicBreuker/cryptanalysis) | Caesar 26-key, Vigenère IoC period, substitution hill-climb | Check repo |

---

## Isomorphs & historical ciphers

| Source | URL | What we document |
|--------|-----|------------------|
| **cryptohelper-isomorphs** | [NBiermann/cryptohelper-isomorphs](https://github.com/NBiermann/cryptohelper-isomorphs) | Isomorph definition, pattern significance, sliding-window algorithm |
| **decipher** | [matthewdgreen/decipher](https://github.com/matthewdgreen/decipher) | Automated solver taxonomy: monoalphabetic, homophonic, periodic polyalphabetic, transposition+homophonic |
| **Lasry / Friedman ring** | [ScienceBlogs challenge](https://scienceblogs.de/klausis-krypto-kolumne/the-friedman-ring-challenge-by-george-lasry/) | Isomorph-driven alphabet reduction |
| **Eyes / Noita** | [Null-H3x/Eyes](https://github.com/Null-H3x/Eyes) | In-depth keystream, depth attack, corpus (bundled in `datasets/unsolved/`) |

---

## Cipher taxonomy reference (not fully implemented)

| Source | URL | Use |
|--------|-----|-----|
| **cipher-detective-ai** | [systemslibrarian/cipher-detective-ai](https://github.com/systemslibrarian/cipher-detective-ai) | 81-type taxonomy for gap analysis; educational heuristics only |
| **Practical Cryptography** | [practicalcryptography.com](https://www.practicalcryptography.com/cryptanalysis/) | Classical attack descriptions (web) |

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

| Source | Reason |
|--------|--------|
| [SebassCoates/Isomorph](https://github.com/SebassCoates/Isomorph) | Graph-theory encryption scheme, not classical isomorph detection |
| [DanielProg39/Key-Space-Brute-Force](https://github.com/DanielProg39/Key-Space-Brute-Force) | Raw n-bit brute force demo; not cipher-specific |

---

## How to extend this list

1. Verify formula or algorithm against our implementation (add KAT in `scripts/math_audit.py`)
2. Add row to this table with URL and validation note
3. Link from [`methods.md`](methods.md) or [`keyspace-reference.md`](keyspace-reference.md)
