"""Entropy, index of coincidence, and language-likeness metrics."""

from __future__ import annotations

import math
from collections import Counter

ENGLISH_IC = 0.067
RANDOM_IC_26 = 0.038
ENGLISH_FREQ: dict[str, float] = {
    "A": 0.08167,
    "B": 0.01492,
    "C": 0.02782,
    "D": 0.04253,
    "E": 0.12702,
    "F": 0.02228,
    "G": 0.02015,
    "H": 0.06094,
    "I": 0.06966,
    "J": 0.00153,
    "K": 0.00772,
    "L": 0.04025,
    "M": 0.02406,
    "N": 0.06749,
    "O": 0.07507,
    "P": 0.01929,
    "Q": 0.00095,
    "R": 0.05987,
    "S": 0.06327,
    "T": 0.09056,
    "U": 0.02758,
    "V": 0.00978,
    "W": 0.02360,
    "X": 0.00150,
    "Y": 0.01974,
    "Z": 0.00074,
}


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def index_of_coincidence(text: str) -> float:
    if len(text) <= 1:
        return 0.0
    freq = Counter(text)
    n = len(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def normalized_ic_ratio(ic: float, *, random_ic: float = RANDOM_IC_26, language_ic: float = ENGLISH_IC) -> float:
    if language_ic == random_ic:
        return 0.0
    return (ic - random_ic) / (language_ic - random_ic)


def chi_squared_english(text: str) -> float | None:
    alpha = [ch.upper() for ch in text if ch.isalpha()]
    if not alpha:
        return None
    n = len(alpha)
    freq = Counter(alpha)
    return sum(((freq.get(ch, 0) - ENGLISH_FREQ[ch] * n) ** 2) / (ENGLISH_FREQ[ch] * n) for ch in ENGLISH_FREQ)


def friedman_key_length_estimate(text: str) -> float | None:
    alpha = [ch.upper() for ch in text if ch.isalpha()]
    n = len(alpha)
    if n < 20:
        return None
    ic = index_of_coincidence("".join(alpha))
    denom = (n - 1) * ic - 0.038 * n + 0.065
    if denom <= 0:
        return None
    return 0.027 * n / denom


def fingerprint_metrics(text: str, *, symbol_class: str) -> dict:
    ic = index_of_coincidence(text) if text else 0.0
    random_ic = 1.0 / max(len(set(text)), 1) if text else RANDOM_IC_26
    if symbol_class == "alpha":
        random_ic = RANDOM_IC_26
        language_ic = ENGLISH_IC
    else:
        language_ic = random_ic * 1.75

    friedman = friedman_key_length_estimate(text) if symbol_class == "alpha" else None

    return {
        "shannon_entropy_bits": round(shannon_entropy(text), 6),
        "index_of_coincidence": round(ic, 6),
        "normalized_ic_ratio": round(normalized_ic_ratio(ic, random_ic=random_ic, language_ic=language_ic), 6),
        "chi_squared_english": round(chi_squared_english(text), 4) if symbol_class == "alpha" else None,
        "friedman_key_length_estimate": round(friedman, 4) if friedman is not None else None,
        "language_ic_reference": language_ic,
        "random_ic_reference": random_ic,
        "unique_symbols": len(set(text)) if text else 0,
    }
