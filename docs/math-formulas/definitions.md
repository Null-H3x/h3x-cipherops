# Cryptographic Variable Definitions

## 📐 Core Variables (Universal)

| Symbol | Meaning | Domain | Notes |
|--------|---------|--------|-------|
| **P** | Plaintext | $\mathcal{P}$ | Message before encryption |
| **C** | Ciphertext | $\mathcal{C}$ | Message after encryption |
| **K** | Key | $\mathcal{K}$ | Secret parameter for cipher |
| **E** | Encryption function | $E_K: \mathcal{P} \to \mathcal{C}$ | $C = E_K(P)$ |
| **D** | Decryption function | $D_K: \mathcal{C} \to \mathcal{P}$ | $P = D_K(C)$ |

## 🔤 Character Mapping Variables

| Symbol | Meaning | Domain | Notes |
|--------|---------|--------|-------|
| **x**, **i**, **j** | Character index | $0, 1, ..., n-1$ | Position in message (0-based) |
| **α**, **β** | Alphabet size | $\mathbb{N}$ | Usually 26 for English A-Z |
| **A** | Alphabet set | ${a_0, a_1, ..., a_{\alpha-1}}$ | Ordered character set |

## 🔑 Key-Specific Variables

| Symbol | Meaning | Domain | Notes |
|--------|---------|--------|-------|
| **k**, **K** | Shift amount / key | $\mathbb{Z}_{\alpha}$ | Caesar, Affine |
| **s** | Substitution mapping | ${0,1}^{\alpha \times \alpha}$ | General substitution cipher |
| **v** | Vigenère key vector | $\mathbb{Z}_{\alpha}^m$ | Repeating key of length m |

## 📊 Statistical / Analysis Variables

| Symbol | Meaning | Formula | Notes |
|--------|---------|---------|-------|
| **IC** | Index of Coincidence | $\frac{\sum_{i=0}^{\alpha-1} n_i(n_i-1)}{n(n-1)}$ | Measures letter frequency bias |
| **H** | Shannon entropy | $-\sum p(x) \log_2 p(x)$ | Bits per symbol |
| **N** | Message length | $|P|$ | Total characters |

## ⚙️ Cipher-Specific Variables

### Caesar / ROT
- **x**: Plaintext character index (A=0, B=1, ..., Z=25)
- **K = k**: Shift key ($0 \leq k < 26$)
- $E_k(x) = (x + k) \mod 26$
- $D_k(y) = (y - k) \mod 26$

### Affine Cipher
- **a**: Multiplicative key ($\gcd(a, 26) = 1$)
- **b**: Additive key ($0 \leq b < 26$)
- $E_{a,b}(x) = (a \cdot x + b) \mod 26$
- $D_{a,b}(y) = a^{-1} \cdot (y - b) \mod 26$

### Vigenère Cipher
- **K = (k_1, k_2, ..., k_m)**: Key vector of length m
- $E_K(x_i) = (x_i + k_{i \mod m}) \mod 26$
- Decryption uses subtraction mod 26

### Playfair Cipher
- **M**: 5×5 matrix (I/J combined)
- **P1, P2**: Plaintext character pair
- **R1, C1**, **R2, C2**: Row/column coordinates
- Rules for rectangle, same row, same column

### Hill Cipher
- **n**: Block size (matrix dimension)
- **H**: $n \times n$ key matrix ($\det(H) \neq 0$)
- $C = H \cdot P \mod 26$
- Requires matrix inverse for decryption

## 📌 Edge Cases & Special Notes

| Variable | Meaning |
|----------|---------|
| **P = C** | Identity cipher (no encryption) |
| **K = 0** | Trivial key (often invalid, skip) |
| **x mod α = x** | When $0 \leq x < \alpha$ |
| **Non-alphabetic chars** | Typically preserved unchanged |
| **Case sensitivity** | Often converted to uppercase for processing |

---

## 📚 Notation Reference

- $\mathbb{Z}_n$: Integers modulo n
- $\gcd(a,b)$: Greatest common divisor
- $a^{-1} \mod n$: Modular multiplicative inverse
- $|S|$ : Cardinality (length) of set S
