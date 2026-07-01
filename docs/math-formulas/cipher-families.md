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

### Symmetric Key
- **AES**: Block, 128 bits, 128/192/256 key
- **ChaCha20**: Stream, 256 bits

### Asymmetric Key
- **RSA**: Integer factorization
- **ECC**: Elliptic curves

### Hash Functions
- **SHA-256**: 256 bit output
