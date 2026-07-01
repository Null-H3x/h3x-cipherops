"""Word and structural pattern features."""

from __future__ import annotations

import re
from collections import Counter


def word_pattern_profile(raw: str, stream_text: str, *, symbol_class: str) -> dict:
    spaces = " " in raw
    punctuation = any(not ch.isalnum() and not ch.isspace() for ch in raw)

    if symbol_class == "alpha" and spaces:
        tokens = [tok for tok in re.split(r"\s+", raw.strip()) if tok]
        lengths = [len("".join(ch for ch in tok if ch.isalpha())) for tok in tokens]
        avg_len = round(sum(lengths) / len(lengths), 4) if lengths else None
        return {
            "preserves_spaces": True,
            "preserves_punctuation": punctuation,
            "word_boundary_markers": [" "],
            "estimated_words": len(tokens),
            "avg_token_length": avg_len,
            "token_length_histogram": dict(Counter(lengths)),
            "repeated_blocks": _repeated_blocks(stream_text),
        }

    if symbol_class == "integer":
        parts = stream_text.split()
        return {
            "preserves_spaces": True,
            "preserves_punctuation": False,
            "word_boundary_markers": [" "],
            "estimated_words": len(parts),
            "avg_token_length": round(len(parts) / max(len(set(parts)), 1), 4) if parts else None,
            "token_length_histogram": {},
            "repeated_blocks": _repeated_blocks(stream_text),
        }

    return {
        "preserves_spaces": spaces,
        "preserves_punctuation": punctuation,
        "word_boundary_markers": [" "] if spaces else [],
        "estimated_words": None,
        "avg_token_length": None,
        "token_length_histogram": {},
        "repeated_blocks": _repeated_blocks(stream_text),
    }


def _repeated_blocks(text: str, min_len: int = 3, max_len: int = 8, top_n: int = 5) -> list[dict]:
    counts: Counter[str] = Counter()
    for n in range(min_len, max_len + 1):
        for i in range(len(text) - n + 1):
            block = text[i : i + n]
            counts[block] += 1
    return [
        {"block": block, "count": count}
        for block, count in counts.most_common(top_n)
        if count > 1
    ]
