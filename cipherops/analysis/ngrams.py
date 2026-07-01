"""N-gram statistics for ciphertext."""

from __future__ import annotations

from collections import Counter


def _top_ngrams(text: str, n: int, *, top_n: int = 10) -> list[list]:
    if len(text) < n:
        return []
    counts = Counter(text[i : i + n] for i in range(len(text) - n + 1))
    total = sum(counts.values())
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:top_n]
    return [[gram, round(count / total, 6)] for gram, count in ranked]


def ngram_profile(text: str, *, top_n: int = 10) -> dict:
    bigram_top = _top_ngrams(text, 2, top_n=top_n)
    trigram_top = _top_ngrams(text, 3, top_n=top_n)
    return {
        "bigram_top": bigram_top,
        "trigram_top": trigram_top,
        "bigram_count": max(0, len(text) - 1),
        "trigram_count": max(0, len(text) - 2),
    }
