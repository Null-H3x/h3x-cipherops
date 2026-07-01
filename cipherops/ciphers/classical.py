"""Classical monoalphabetic and polyalphabetic cipher implementations."""

from __future__ import annotations

from cipherops.ciphers.utils import (
    ALPHABET,
    char_index,
    clean_alpha,
    index_char,
    mod_inverse,
    preserve_case,
)


def atbash(text: str) -> str:
    """E(x) = (25 - x) mod 26. Self-reciprocal."""
    transformed = "".join(index_char(25 - char_index(c)) for c in clean_alpha(text))
    return preserve_case(text, transformed)


def caesar(text: str, shift: int) -> str:
    """E_k(x) = (x + k) mod 26."""
    transformed = "".join(index_char(char_index(c) + shift) for c in clean_alpha(text))
    return preserve_case(text, transformed)


def rot13(text: str) -> str:
    return caesar(text, 13)


def affine(text: str, a: int, b: int) -> str:
    """E_{a,b}(x) = (a*x + b) mod 26."""
    if __import__("math").gcd(a, 26) != 1:
        raise ValueError(f"Invalid affine key a={a}; gcd(a,26) must be 1")
    transformed = "".join(index_char(a * char_index(c) + b) for c in clean_alpha(text))
    return preserve_case(text, transformed)


def affine_decrypt(text: str, a: int, b: int) -> str:
    a_inv = mod_inverse(a)
    transformed = "".join(index_char(a_inv * (char_index(c) - b)) for c in clean_alpha(text))
    return preserve_case(text, transformed)


def beaufort(text: str, key: str) -> str:
    """E(x) = (k - x) mod 26. Self-reciprocal."""
    key = clean_alpha(key)
    if not key:
        raise ValueError("Beaufort key required")
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(key[ki % len(key)])
            out.append(index_char(k - char_index(ch), upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere(text: str, key: str) -> str:
    """E_K(x_i) = (x_i + k_{i mod m}) mod 26."""
    key = clean_alpha(key)
    if not key:
        raise ValueError("Vigenere key required")
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(key[ki % len(key)])
            out.append(index_char(char_index(ch) + k, upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_decrypt(text: str, key: str) -> str:
    key = clean_alpha(key)
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(key[ki % len(key)])
            out.append(index_char(char_index(ch) - k, upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def gronsfeld(text: str, numeric_key: str) -> str:
    """Vigenere variant with decimal digit shifts."""
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("Gronsfeld key must be numeric")
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = int(numeric_key[ki % len(numeric_key)])
            out.append(index_char(char_index(ch) + k, upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def gronsfeld_decrypt(text: str, numeric_key: str) -> str:
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("Gronsfeld key must be numeric")
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = int(numeric_key[ki % len(numeric_key)])
            out.append(index_char(char_index(ch) - k, upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def nihilist(text: str, numeric_key: str, *, polybius_key: str = "NIHILIST") -> str:
    """
    Nihilist cipher: Polybius coordinates + numeric key addition mod 10 per digit.
    """
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("Nihilist key must be numeric")
    from cipherops.ciphers.utils import build_polybius_square, polybius_coords

    square = build_polybius_square(polybius_key, size=5)
    digits: list[str] = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            r, c = polybius_coords(square, ch)
            d1, d2 = r + 1, c + 1
            k1 = int(numeric_key[ki % len(numeric_key)])
            k2 = int(numeric_key[(ki + 1) % len(numeric_key)])
            digits.append(str((d1 + k1) % 10))
            digits.append(str((d2 + k2) % 10))
            ki += 2
        else:
            digits.append(ch)
    return "".join(digits)


def nihilist_decrypt(text: str, numeric_key: str, *, polybius_key: str = "NIHILIST") -> str:
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("Nihilist key must be numeric")
    from cipherops.ciphers.utils import build_polybius_square

    square = build_polybius_square(polybius_key, size=5)
    digits = "".join(ch for ch in text if ch.isdigit())
    ki = 0
    letters: list[str] = []
    for i in range(0, len(digits), 2):
        d1 = int(digits[i])
        d2 = int(digits[i + 1])
        k1 = int(numeric_key[ki % len(numeric_key)])
        k2 = int(numeric_key[(ki + 1) % len(numeric_key)])
        r = (d1 - k1) % 10
        c = (d2 - k2) % 10
        if not 1 <= r <= 5 or not 1 <= c <= 5:
            raise ValueError(f"Invalid Polybius coordinates after decrypt: {r},{c}")
        letters.append(square[r - 1][c - 1])
        ki += 2
    out: list[str] = []
    li = 0
    di = 0
    for ch in text:
        if ch.isdigit():
            if di % 2 == 0:
                out.append(letters[li])
                li += 1
            di += 1
        else:
            out.append(ch)
    return "".join(out)


def autokey(text: str, key: str, *, variant: str = "standard") -> str:
    """
    Autokey cipher variants:
    - standard: keystream = key || plaintext (Vigenere-style addition)
    - beaufort: keystream = key || plaintext with Beaufort subtraction
    """
    key = clean_alpha(key)
    if not key:
        raise ValueError("Autokey key required")
    alpha = clean_alpha(text)
    stream = list(key + alpha[:-1])
    out = []
    ai = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(stream[ai])
            if variant == "beaufort":
                out.append(index_char(k - char_index(ch), upper=ch.isupper()))
            else:
                out.append(index_char(char_index(ch) + k, upper=ch.isupper()))
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def autokey_decrypt(text: str, key: str, *, variant: str = "standard") -> str:
    key = clean_alpha(key)
    stream = list(key)
    out = []
    ai = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(stream[ai])
            if variant == "beaufort":
                plain_idx = (k - char_index(ch)) % 26
            else:
                plain_idx = (char_index(ch) - k) % 26
            plain_char = index_char(plain_idx, upper=ch.isupper())
            out.append(plain_char)
            stream.append(index_char(plain_idx))
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def running_key(text: str, key_text: str) -> str:
    """Vigenere with non-repeating keystream from a long text."""
    key = clean_alpha(key_text)
    if len(key) < len(clean_alpha(text)):
        raise ValueError("Running key text must be at least as long as plaintext")
    return vigenere(text, key[: len(clean_alpha(text))])


def running_key_decrypt(text: str, key_text: str) -> str:
    key = clean_alpha(key_text)
    return vigenere_decrypt(text, key[: len(clean_alpha(text))])


def porta(text: str, key: str) -> str:
    """Porta cipher using the standard 13-alphabet reciprocal table."""
    key = clean_alpha(key)
    if not key:
        raise ValueError("Porta key required")
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(key[ki % len(key)]) % 13
            x = char_index(ch)
            if x < 13:
                y = (x + k) % 13 + 13
            else:
                y = (x - 13 - k) % 13
            out.append(index_char(y, upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def simple_substitution(text: str, mapping: str) -> str:
    """Encrypt with a 26-letter substitution alphabet."""
    mapping = mapping.upper()
    if len(set(mapping)) != 26 or len(mapping) != 26:
        raise ValueError("Substitution mapping must be 26 unique letters")
    table = {plain: mapping[i] for i, plain in enumerate(ALPHABET)}
    out = []
    for ch in text:
        if ch.isalpha():
            mapped = table[ch.upper()]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    return "".join(out)


def simple_substitution_decrypt(text: str, mapping: str) -> str:
    mapping = mapping.upper()
    inverse = {mapping[i]: ALPHABET[i] for i in range(26)}
    out = []
    for ch in text:
        if ch.isalpha():
            mapped = inverse[ch.upper()]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    return "".join(out)


def homophonic_substitution(text: str, mapping: dict[str, str]) -> str:
    """
    Homophonic cipher: each plaintext letter maps to one chosen homophone.
    mapping example: {'A': '01', 'B': '12', ...}
    """
    out = []
    for ch in text:
        if ch.isalpha():
            out.append(mapping.get(ch.upper(), ch.upper()))
        else:
            out.append(ch)
    return "".join(out)


def homophonic_substitution_decrypt(text: str, inverse: dict[str, str]) -> str:
    digits = "".join(ch for ch in text if ch.isdigit())
    out = []
    i = 0
    while i < len(digits):
        token = digits[i : i + 2]
        if token in inverse:
            out.append(inverse[token])
            i += 2
        elif digits[i] in inverse:
            out.append(inverse[digits[i]])
            i += 1
        else:
            i += 1
    return "".join(out)


def baconian_encode(text: str, *, a_char: str = "A", b_char: str = "B") -> str:
    """Encode letters to Bacon biliteral groups (5 bits each)."""
    bacon_map = {
        "A": "AAAAA",
        "B": "AAAAB",
        "C": "AAABA",
        "D": "AAABB",
        "E": "AABAA",
        "F": "AABAB",
        "G": "AABBA",
        "H": "AABBB",
        "I": "ABAAA",
        "J": "ABAAB",
        "K": "ABABA",
        "L": "ABABB",
        "M": "ABBAA",
        "N": "ABBAB",
        "O": "ABBBA",
        "P": "ABBBB",
        "Q": "BAAAA",
        "R": "BAAAB",
        "S": "BAABA",
        "T": "BAABB",
        "U": "BABAA",
        "V": "BABAB",
        "W": "BABBA",
        "X": "BABBB",
        "Y": "BBAAA",
        "Z": "BBAAB",
    }
    return "".join(
        bacon_map[ch.upper()].replace("A", a_char).replace("B", b_char)
        for ch in clean_alpha(text)
    )


def baconian_decode(text: str, *, a_char: str = "A", b_char: str = "B") -> str:
    inverse = {
        "AAAAA": "A",
        "AAAAB": "B",
        "AAABA": "C",
        "AAABB": "D",
        "AABAA": "E",
        "AABAB": "F",
        "AABBA": "G",
        "AABBB": "H",
        "ABAAA": "I",
        "ABAAB": "J",
        "ABABA": "K",
        "ABABB": "L",
        "ABBAA": "M",
        "ABBAB": "N",
        "ABBBA": "O",
        "ABBBB": "P",
        "BAAAA": "Q",
        "BAAAB": "R",
        "BAABA": "S",
        "BAABB": "T",
        "BABAA": "U",
        "BABAB": "V",
        "BABBA": "W",
        "BABBB": "X",
        "BBAAA": "Y",
        "BBAAB": "Z",
    }
    normalized = text.upper().replace(a_char.upper(), "A").replace(b_char.upper(), "B")
    normalized = "".join(ch for ch in normalized if ch in "AB")
    return "".join(inverse[normalized[i : i + 5]] for i in range(0, len(normalized), 5))


def polybius_square(text: str, key: str = "") -> str:
    """Map letters to row/column digit pairs (1-indexed)."""
    from cipherops.ciphers.utils import build_polybius_square, polybius_coords

    square = build_polybius_square(key, size=5)
    pairs = []
    for ch in clean_alpha(text):
        r, c = polybius_coords(square, ch)
        pairs.append(f"{r + 1}{c + 1}")
    return " ".join(pairs)


def polybius_square_decrypt(text: str, key: str = "") -> str:
    from cipherops.ciphers.utils import build_polybius_square

    square = build_polybius_square(key, size=5)
    digits = "".join(ch for ch in text if ch.isdigit())
    out = []
    for i in range(0, len(digits), 2):
        r = int(digits[i]) - 1
        c = int(digits[i + 1]) - 1
        out.append(square[r][c])
    return "".join(out)


def nomenclator_encode(text: str, codebook: dict[str, str]) -> str:
    """Encode words/phrases using a nomenclator codebook."""
    words = text.split()
    return " ".join(codebook.get(word.upper(), word) for word in words)


def nomenclator_decode(text: str, codebook: dict[str, str]) -> str:
    inverse = {v: k for k, v in codebook.items()}
    tokens = text.split()
    return " ".join(inverse.get(token, token) for token in tokens)
