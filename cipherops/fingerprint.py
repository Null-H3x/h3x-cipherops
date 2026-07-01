"""
fingerprint.py — Entropy, Index of Coincidence, Kasiski examination.

Functions:
- shannon_entropy(data: str) -> float
- index_of_coincidence(text: str) -> float
- kasiski_examination(ciphertext: str, max_len: int = 30) -> list[int]
"""

import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (bits per symbol)."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def index_of_coincidence(text: str) -> float:
    """Calculate IC of text (higher ~ lower entropy, more structure)."""
    # Normalize to uppercase letters only
    clean = [c.upper() for c in text if c.isalpha()]
    if len(clean) <= 1:
        return 0.0
    freq = Counter(clean)
    n = len(clean)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def kasiski_examination(ciphertext: str, max_len: int = 30) -> list[int]:
    """
    Find likely key lengths using repeated trigrams.
    Returns a sorted list of candidate key lengths.
    """
    # Find repeated trigams
    repeats = {}
    for i in range(len(ciphertext) - 2):
        trig = ciphertext[i : i + 3]
        if trig.isalpha():
            positions = [
                j for j in range(i + 1, len(ciphertext) - 2)
                if ciphertext[j : j + 3] == trig
            ]
            for pos in positions:
                dist = pos - i
                repeats.setdefault(trig, []).append(dist)

    # Collect distances and find GCDs
    all_dists = [d for dists in repeats.values() for d in dists]
    if not all_dists:
        return []

    # Factor distances (simple: check divisibility up to max_len)
    candidates = []
    for k in range(2, min(max_len + 1, 50)):
        if all(d % k == 0 for d in all_dists):
            candidates.append(k)

    return sorted(set(candidates))
