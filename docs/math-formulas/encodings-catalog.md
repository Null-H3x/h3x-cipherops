# Encodings Catalog

Line codes, radix encodings, and physical-layer mappings — **distinct from ciphers** (no secret key). This repo implements a subset as fingerprinted datasets for LLM training; others are reference-only.

**Implemented:** Base64, Baconian, PAM-5 dibit, Hex (UTF-8), Manchester (IEEE 802.3).  
**See also:** [`cipher-families.md`](cipher-families.md), [`unimplemented-ciphers.md`](unimplemented-ciphers.md).

---

## Status legend

| Status | Meaning |
|--------|---------|
| **Implemented** | `cipherops` + math doc + dataset |
| **Reference** | Documented formula; no dataset yet |
| **PHY** | Physical layer; typically not classical cryptanalysis |

---

## Radix & binary-to-text encodings

| Encoding | Radix / alphabet | Bits per symbol | Status | Notes |
|----------|------------------|-----------------|--------|-------|
| **Base64** | 64 (+ padding `=`) | 6 | Implemented (`b64`) | RFC 4648 |
| **Base32** | 32 (A–Z2–7) | 5 | Reference | RFC 4648, case-insensitive |
| **Base58** | 58 (Bitcoin alphabet) | ~5.86 | Reference | No 0/O/I/l |
| **Hexadecimal** | 16 (0–9A–F) | 4 | **Implemented** (`hex-utf8`) | Nibble encoding |
| **Binary** | 2 (0/1) | 1 | Reference | Raw bit strings |
| **Octal** | 8 (0–7) | 3 | Reference | Unix file modes, legacy |

---

## PAM & line codes (physical / data link)

| Encoding | Levels / states | Typical use | Status | Formula sketch |
|----------|-----------------|-------------|--------|----------------|
| **PAM-5 dibit** | 5 levels; 4 used for data | 1000BASE-T teaching model | **Implemented** (`pam5-dibit`) | 2 bits → level \(\in\{0,1,2,3\}\) |
| **4D-PAM5** | 4 symbols × 5 levels per 8 bits | Gigabit Ethernet PHY | Reference (PHY) | 8 bits → \((s_1,s_2,s_3,s_4)\) each \(s_i \in \mathcal{L}_5\) |
| **NRZ** | 2 (high/low) | Digital storage | Reference | Bit → voltage |
| **NRZ-I** | 2 (transition = 1) | Magnetic tape | Reference | Invert on 1 |
| **Manchester** | 2 (mid-bit transition) | 10BASE-T, RFID | **Implemented** (`manchester-ieee`) | 0 = 01, 1 = 10 per bit period |
| **Differential Manchester** | 2 | Token Ring | Reference | Transition at start = 0 |
| **8b/10b** | 256→1024 codewords | PCIe, SATA | Reference | DC balance + clock recovery |
| **4b/5b** | 16→32 codewords | Fast Ethernet (with NRZI) | Reference | Complements NRZI |
| **Gray code** | Binary adjacency | Rotary encoders | Reference | One bit flip per step |

### PAM-5 detail

Five amplitude levels; \(\log_2 5 \approx 2.32\) bits/symbol theoretical capacity.

**Dibit mapping (this repo):**

```
00 → 0,  01 → 1,  10 → 2,  11 → 3   (level 4 reserved)
```

**4D-PAM5 (IEEE 802.3):** each byte split into four 2-bit groups, each group drives one PAM-5 symbol on a wire pair — requires trellis coding and Viterbi decode at PHY; not replicated here.

---

## Telecommunications & historical

| Encoding | Type | Status | Notes |
|----------|------|--------|-------|
| **Baudot / ITA2** | 5-bit character code | Reference | Murray teleprinter |
| **Morse** | Variable-length dit/dah | Reference | [`fractionated-morse.md`](fractionated-morse.md) compound |
| **Baconian (A/B)** | 5 bits → 2 letters | Implemented | Steganography channel |
| **ASCII / UTF-8** | Character sets | Reference | Plaintext representation |

---

## Steganographic / biliteral channels

| Scheme | Channel | Status |
|--------|---------|--------|
| Baconian font | Typography (A/B style) | Implemented |
| Null cipher | Word position / nth letter | Reference |
| Acrostic | First letters spell message | Reference |

---

## Implementation mapping

| Encoding | Code | Math doc | Dataset slug |
|----------|------|----------|----------------|
| Base64 | `encoding.base64_encode` | [`base64.md`](base64.md) | `b64` |
| Baconian | `classical.baconian_encode` | [`baconian.md`](baconian.md) | `baconian-ab` |
| PAM-5 dibit | `encoding.pam5_encode` | [`pam5.md`](pam5.md) | `pam5-dibit` |
| Hex (UTF-8) | `encoding.hex_encode` | [`hex.md`](hex.md) | `hex-utf8` |
| Manchester IEEE | `encoding.manchester_encode` | [`manchester.md`](manchester.md) | `manchester-ieee` |

---

## Keyspace (all encodings)

\(|K| = 1\) — deterministic reversible maps. See [`../cryptanalysis/keyspace-reference.md`](../cryptanalysis/keyspace-reference.md).

---

## Suggested implementation order

1. Base32 / Base58 (simple radix, puzzle frequency)
2. 4D-PAM5 trellis (PHY-accurate, high effort)
