# Cipher Families Classification

## 📜 Classical Ciphers (Pre-20th Century)

### A

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **ADFGVX cipher** | Fractionation | Grid mapping + transposition | 6x6 matrix, uses A-D-G-V-X letters |
| **Affine cipher** | Substitution | E(x) = (a*x + b) mod 26 | Requires gcd(a, 26) = 1 |
| **Atbash** | Substitution | E(x) = (25 - x) mod 26 | Self-reciprocal |

### B

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **Bacon's cipher** | Biliteral substitution | Binary encoding (A/B) | Hidden message in font/style |
| **Beaufort cipher** | Vigenere variant | E(x) = (k - x) mod 26 | Reciprocal cipher |

### C

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **Caesar cipher** | Shift substitution | E(x) = (x + k) mod 26 | ROT13 is self-inverse |
| **Copiale cipher** | Symbol substitution | Arbitrary symbol mapping | Mysterious manuscript |

### D

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **DRYAD** | Stream cipher | XOR with keystream | US military, WWII era |

### F

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **Four-square cipher** | Digraph substitution | 4 matrix grid | Encrypts pairs of letters |

### G

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **Grille cipher** | Transposition | Physical hole pattern | Cardboard grille over text |

### H

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **Hill cipher** | Matrix substitution | C = H * P mod 26 | First true polygraphic cipher |

### M

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **M-94** | Cylinder cipher | Rotating drum alignment | US military, WWII |

### N

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **Nihilist cipher** | Polybius-based | Matrix coordinates + addition | Uses 5x5 Polybius square |

### P

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **Pigpen cipher** | Symbol substitution | Grid-based symbols | Freemason symbol set |
| **Playfair cipher** | Digraph substitution | Rectangle rule on 5x5 matrix | British military, Boer War |
| **Polybius square** | Coordinate system | (row, col) mapping | Basis for many ciphers |

### R

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **Rail fence cipher** | Transposition | Zigzag pattern writing | Simple row permutation |
| **ROT13** | Shift substitution | E(x) = (x + 13) mod 26 | Self-inverse |

### S

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **Scytale** | Transposition | Cylindrical winding | Ancient Greek, staff-based |

### T

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **Transposition cipher** | Permutation | pi: {0,...,n-1} -> {0,...,n-1} | Reorders characters |

### V

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **VIC cipher** | Complex cipher | Multiple stages (sub + transp) | Soviet spy cipher, 1950s |
| **Vigenere cipher** | Polyalphabetic | E_i(x) = (x + k_{i mod m}) mod 26 | Key repeats every m chars |

### W

| Cipher | Type | Math Formula | Notes |
|--------|------|--------------|-------|
| **Wahlwort cipher** | Word substitution | Predefined word codes | German WWII, codeword system |

---

## Modern Ciphers (20th Century+)

### Symmetric Block & Stream
| Cipher | Type | Math Formula | Dataset Slug |
|--------|------|--------------|--------------|
| **AES-GCM** | AEAD block | CTR + GHASH authentication | `aes-128-gcm`, `aes-256-gcm` |
| **AES-CBC** | Block mode | $C_i = E_K(P_i \oplus C_{i-1})$ | `aes-128-cbc`, `aes-256-cbc` |
| **AES-CTR** | Stream from block | $C = P \oplus E_K(\text{nonce}\|\text{counter})$ | `aes-128-ctr` |
| **ChaCha20-Poly1305** | AEAD stream | ChaCha20 + Poly1305 MAC | `chacha20-poly1305` |
| **3DES-CBC** | Legacy block | Triple-DES EDE chain | `tripledes-cbc` |
| **Fernet** | Authenticated token | AES-CBC + HMAC-SHA256 | `fernet` |
| **XOR-SHA256 stream** | Stream | SHA256 counter keystream | `xor-sha256-stream` |

### Key Derivation
| Cipher | Type | Math Formula | Dataset Slug |
|--------|------|--------------|--------------|
| **PBKDF2** | KDF + AES-GCM | Password-based stretching | `pbkdf2-aes-gcm` |
| **HKDF** | KDF + AES-GCM | Extract-and-expand (RFC 5869) | `hkdf-aes-gcm` |

### Asymmetric
| Cipher | Type | Math Formula | Dataset Slug |
|--------|------|--------------|--------------|
| **RSA-OAEP hybrid** | Public-key + symmetric | RSA-OAEP wraps AES key | `rsa-oaep-hybrid` |
| **Ed25519** | Signatures | Edwards-curve Schnorr | `ed25519-sign` |
| **X25519** | ECDH | Curve25519 scalar multiply | `x25519-ecdh` |

### Hash & MAC (one-way)
| Cipher | Type | Math Formula | Dataset Slug |
|--------|------|--------------|--------------|
| **SHA-256** | Hash | Merkle-Damgård 256-bit | `sha256` |
| **SHA-512** | Hash | Merkle-Damgård 512-bit | `sha512` |
| **SHA3-256** | Hash | Keccak sponge | `sha3-256` |
| **BLAKE2b** | Hash | ARX hash 512-bit | `blake2b` |
| **HMAC-SHA256** | MAC | Keyed hash | `hmac-sha256` |

### Previously documented
- **AES**: Block, 128 bits, 128/192/256 key
- **ChaCha20**: Stream, 256 bits
- **RSA**: Integer factorization
- **ECC**: Elliptic curves
