# Math Formulas Documentation

Mathematical definitions, variables, and validated Python implementations for classical ciphers used in CipherOps.

## Core Reference

| File | Description |
|------|-------------|
| [`../variable-inventory.md`](../variable-inventory.md) | **Full variable & field inventory** (datasets, properties, cipher registry) |
| `definitions.md` | Universal notation (P, C, K, x, k) |
| `cipher-families.md` | Cipher taxonomy and quick reference |
| `encodings-catalog.md` | Line codes & radix encodings (PAM-5, NRZ, Manchester, …) |
| `unimplemented-ciphers.md` | Reference catalog for ciphers not yet in registry |

## Cipher Formula Files

| Cipher | File | Dataset Slug |
|--------|------|--------------|
| Atbash | `atbash.md` | `atbash` |
| Caesar / ROT13 | `caesar.md` | `caesar-rot3`, `caesar-rot13` |
| Affine | `affine.md` | `affine-a2b5` |
| Rail Fence | `railfence.md` | `railfence-3` |
| Scytale | `scytale.md` | `scytale-d5` |
| Pigpen | `pigpen.md` | `pigpen-standard` |
| Baconian | `baconian.md` | `baconian-ab` |
| Polybius Square | `polybius.md` | `polybius-square` |
| Simple Substitution | `substitution.md` | `substitution-qwerty` |
| Nomenclator | `nomenclator.md` | `nomenclator-basic` |
| Columnar Transposition | `columnar.md` | `columnar-keyword` |
| Autokey | `autokey.md` | `autokey-standard`, `autokey-beaufort`, `autokey-ciphertext`, `autokey-ciphertext-beaufort` |
| GAK (Eyes) | `gak.md` | `gak-ctak-right-s42`, `gak-ptak-right-s42` |
| XGAK (Eyes) | `xgak.md` | `xgak-sum-right-s42`, `xgak-diff-right-s42` |
| Gronsfeld autokey | `gronsfeld-autokey.md` | `gronsfeld-autokey-31415`, `gronsfeld-autokey-ct-31415` |
| Beaufort | `beaufort.md` | `beaufort-keyword` |
| Porta | `porta.md` | `porta-keyword` |
| Running Key | `running-key.md` | `running-key-book` |
| Vigenère | `vigenere.md` | `vigenere-keyword` |
| Gronsfeld | `gronsfeld.md` | `gronsfeld-31415` |
| Nihilist | `nihilist.md` | `nihilist-31415` |
| Homophonic | `homophonic.md` | `homophonic-basic` |
| Four-Square | `four-square.md` | `four-square-keys` |
| Hill | `hill.md` | `hill-2x2` |
| Playfair | `playfair.md` | `playfair-keyword` |
| ADFGVX | `adfgvx.md` | `adfgvx-keys` |
| ADFGX | `adfgx.md` | `adfgx-keys` |
| Bifid | `bifid.md` | `bifid-keyword` |
| Straddle Checkerboard | `straddle-checkerboard.md` | `straddle-default` |
| Trifid | `trifid.md` | `trifid-keyword` |
| Base64 | `base64.md` | `b64` |
| PAM-5 dibit | `pam5.md` | `pam5-dibit` |
| Hex (UTF-8) | `hex.md` | `hex-utf8` |
| Manchester IEEE | `manchester.md` | `manchester-ieee` |
| Fractionated Morse | `fractionated-morse.md` | `fractionated-morse` |

## Modern Key Ciphers

| Cipher | File | Dataset Slug(s) |
|--------|------|-------------------|
| AES-GCM | `aes-gcm.md` | `aes-128-gcm`, `aes-256-gcm` |
| AES-CBC | `aes-cbc.md` | `aes-128-cbc`, `aes-256-cbc` |
| AES-CTR | `aes-ctr.md` | `aes-128-ctr` |
| ChaCha20-Poly1305 | `chacha20-poly1305.md` | `chacha20-poly1305` |
| Triple DES | `tripledes.md` | `tripledes-cbc` |
| Fernet | `fernet.md` | `fernet` |
| XOR-SHA256 Stream | `xor-stream.md` | `xor-sha256-stream` |
| PBKDF2 | `pbkdf2.md` | `pbkdf2-aes-gcm` |
| HKDF | `hkdf.md` | `hkdf-aes-gcm` |
| RSA-OAEP Hybrid | `rsa.md` | `rsa-oaep-hybrid` |
| Ed25519 | `ed25519.md` | `ed25519-sign` |
| X25519 ECDH | `x25519.md` | `x25519-ecdh` |
| SHA-256 | `sha256.md` | `sha256` |
| SHA-512 | `sha512.md` | `sha512` |
| SHA3-256 | `sha3-256.md` | `sha3-256` |
| BLAKE2b | `blake2b.md` | `blake2b` |
| HMAC-SHA256 | `hmac-sha256.md` | `hmac-sha256` |

## Unsolved Corpora

| Corpus | File | Dataset Path |
|--------|------|--------------|
| Noita Eye Messages | `noita-eye.md` | `datasets/unsolved/noita-eye-messages/data.jsonl` |

## Implementation Source

All formulas map to validated code in `cipherops/ciphers/` and reproducible datasets under `datasets/fingerprinted/`.

Regenerate datasets:

```bash
PYTHONPATH=. python3 scripts/generate_datasets.py
PYTHONPATH=. python3 scripts/validate_datasets.py
```
