"""Symbol frequency analysis."""

from __future__ import annotations

from collections import Counter


def frequency_profile(text: str, *, top_n: int = 10) -> dict:
    if not text:
        return {"unigram": {}, "top_unigrams": [], "total_symbols": 0}

    counts = Counter(text)
    total = len(text)
    unigram = {sym: round(count / total, 6) for sym, count in counts.items()}
    top = sorted(unigram.items(), key=lambda item: (-item[1], item[0]))[:top_n]
    return {
        "unigram": dict(sorted(unigram.items())),
        "top_unigrams": [[sym, freq] for sym, freq in top],
        "total_symbols": total,
    }
