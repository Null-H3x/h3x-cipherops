"""Autokey seed recovery helpers (educational / analysis tooling)."""

from __future__ import annotations

from cipherops.ciphers.classical import autokey_decrypt, gronsfeld_autokey_decrypt
from cipherops.ciphers.utils import clean_alpha


def _english_score(text: str) -> float:
    """Simple unigram log-score for A–Z text (higher = more English-like)."""
    freq = {
        "E": 12.7,
        "T": 9.1,
        "A": 8.2,
        "O": 7.5,
        "I": 7.0,
        "N": 6.7,
        "S": 6.3,
        "H": 6.1,
        "R": 6.0,
        "D": 4.3,
        "L": 4.0,
        "C": 2.8,
        "U": 2.8,
        "M": 2.4,
        "W": 2.4,
        "F": 2.2,
        "G": 2.0,
        "Y": 2.0,
        "P": 1.9,
        "B": 1.5,
        "V": 1.0,
        "K": 0.8,
        "J": 0.15,
        "X": 0.15,
        "Q": 0.10,
        "Z": 0.07,
    }
    alpha = clean_alpha(text)
    if not alpha:
        return float("-inf")
    return sum(freq.get(ch, 0.1) for ch in alpha) / len(alpha)


def brute_force_autokey_seed(
    ciphertext: str,
    seed_length: int,
    *,
    variant: str = "standard",
    extension: str = "plaintext",
    top_n: int = 10,
) -> list[dict]:
    """
    Enumerate all alphabetic priming keys of length ``seed_length``; score decrypted prefix.

    Returns top candidates by English unigram score on full decrypt.
    """
    if seed_length < 1 or seed_length > 4:
        raise ValueError("seed_length must be 1–4 for brute enumeration (26^n grows quickly)")
    ct = ciphertext
    results: list[dict] = []

    def _recurse(prefix: str) -> None:
        if len(prefix) == seed_length:
            try:
                plain = autokey_decrypt(ct, prefix, variant=variant, extension=extension)
            except ValueError:
                return
            score = _english_score(plain)
            results.append({"seed": prefix, "plaintext": plain, "score": score})
            return
        for o in range(26):
            _recurse(prefix + chr(ord("A") + o))

    _recurse("")
    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:top_n]


def brute_force_gronsfeld_autokey_seed(
    ciphertext: str,
    seed_length: int,
    *,
    extension: str = "plaintext",
    top_n: int = 10,
) -> list[dict]:
    """Enumerate numeric priming keys for Gronsfeld autokey (10^n); score full decrypt."""
    if seed_length < 1 or seed_length > 6:
        raise ValueError("seed_length must be 1–6 for numeric brute enumeration")
    ct = ciphertext
    results: list[dict] = []

    def _recurse(prefix: str) -> None:
        if len(prefix) == seed_length:
            try:
                plain = gronsfeld_autokey_decrypt(ct, prefix, extension=extension)
            except ValueError:
                return
            score = _english_score(plain)
            results.append({"seed": prefix, "plaintext": plain, "score": score})
            return
        for d in "0123456789":
            _recurse(prefix + d)

    _recurse("")
    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:top_n]
