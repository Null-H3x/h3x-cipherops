# Affine Cipher

## 📐 Mathematical Definition

The affine cipher uses modular arithmetic with a multiplicative and additive key.

### Encryption Function

$$E_{a,b}(x) = (a \\cdot x + b) \\mod 26$$

Where:
- $x$ = plaintext character index (A=0, B=1, ..., Z=25)
- $a$ = multiplicative key ($\\gcd(a, 26) = 1$, so $a \\in \\{1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25\\}$)
- $b$ = additive key ($0 \\leq b < 26$)

### Decryption Function

$$D_{a,b}(y) = a^{-1} \\cdot (y - b) \\mod 26$$

Where:
- $a^{-1}$ = modular multiplicative inverse of $a$ mod 26
- $y$ = ciphertext character index

## 🔑 Modular Inverse Table (mod 26)

| a | a^(-1) mod 26 |
|---|---------------|
| 1   | 1                 |
| 3   | 9                 |
| 5   | 21                |
| 7   | 15                |
| 9   | 3                 |
| 11  | 19                |
| 15  | 7                 |
| 17  | 23                |
| 19  | 11                |
| 21  | 5                 |
| 23  | 17                |
| 25  | 25                |

## 💻 Python Implementation

```python
def extended_gcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return (b, 0, 1)
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    """Compute modular multiplicative inverse of a mod m."""
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist for a={a} mod {m}")
    return (x % m + m) % m

def affine_encrypt(text, a, b):
    """Encrypt text using affine cipher with keys a and b."""
    result = ""
    for char in text:
        if char.isalpha():
            x = ord(char.upper()) - ord('A')
            y = (a * x + b) % 26
            result += chr(y + ord('A'))
        else:
            result += char
    return result

def affine_decrypt(text, a, b):
    """Decrypt affine cipher with keys a and b."""
    a_inv = mod_inverse(a, 26)
    result = ""
    for char in text:
        if char.isalpha():
            y = ord(char.upper()) - ord('A')
            x = (a_inv * (y - b)) % 26
            result += chr(x + ord('A'))
        else:
            result += char
    return result

# Example usage
plaintext = "HELLO WORLD"
ciphertext = affine_encrypt(plaintext, a=5, b=8)  # E(x) = (5x + 8) mod 26
print(ciphertext)  # RCLLA OAPLX

decrypted = affine_decrypt(ciphertext, a=5, b=8)
print(decrypted)   # HELLO WORLD
```

## 🔍 Cryptanalysis Notes

- **Key space**: 12 valid values for $a$ × 26 values for $b$ = **312 keys**
- **Attack method**: 
  - Known plaintext attack: Solve two equations with two unknowns
  - Brute force: Try all 312 key combinations
  - Frequency analysis: Monoalphabetic substitution pattern preserved

## 📊 Example Encryption (a=5, b=8)

| $x$ | H(7) | E(4) | L(11)| L(11)| O(14)| W(22)| O(14)| R(17)| L(11)| D(3) |
|-----|------|------|------|------|------|------|------|------|------|------|
| $5x$ | 35   | 20   | 55   | 55   | 70   | 110  | 70   | 85   | 55   | 15   |
| $5x+8$ | 43   | 28   | 63   | 63   | 78   | 118  | 78   | 93   | 63   | 23   |
| mod 26 | 17(R)| 2(C) | 11(L)| 11(L)| 0(A) | 14(O)| 0(A) | 15(P)| 11(L)| 23(X) |

**Ciphertext**: RCLLA OAPLX
