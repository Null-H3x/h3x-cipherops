"""Normalize ciphertext into analysis-friendly symbol streams."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisStream:
    raw: str
    text: str
    symbol_class: str
    alphabet_size: int
    preserves_spaces: bool
    preserves_punctuation: bool


def _is_mostly_hex(text: str) -> bool:
    stripped = re.sub(r"\s+", "", text)
    if len(stripped) < 8:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", stripped))


def _is_base64ish(text: str) -> bool:
    stripped = re.sub(r"\s+", "", text)
    if len(stripped) < 8:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", stripped):
        return False
    try:
        base64.b64decode(stripped, validate=True)
        return True
    except Exception:
        return False


def normalize_stream(ciphertext: str | list[int], *, deck_size: int | None = None) -> AnalysisStream:
    if isinstance(ciphertext, list):
        values = [int(x) for x in ciphertext]
        text = " ".join(str(v) for v in values)
        size = deck_size or (max(values) + 1 if values else 0)
        return AnalysisStream(
            raw=text,
            text=text,
            symbol_class="integer",
            alphabet_size=size,
            preserves_spaces=True,
            preserves_punctuation=False,
        )

    raw = str(ciphertext)
    alpha = "".join(ch.upper() for ch in raw if ch.isalpha())
    if len(alpha) >= max(4, len(raw) // 3):
        return AnalysisStream(
            raw=raw,
            text=alpha,
            symbol_class="alpha",
            alphabet_size=26,
            preserves_spaces=" " in raw,
            preserves_punctuation=any(not ch.isalnum() and not ch.isspace() for ch in raw),
        )

    if _is_mostly_hex(raw):
        hex_clean = re.sub(r"\s+", "", raw).upper()
        return AnalysisStream(
            raw=raw,
            text=hex_clean,
            symbol_class="hex",
            alphabet_size=16,
            preserves_spaces=False,
            preserves_punctuation=False,
        )

    if _is_base64ish(raw):
        b64_clean = re.sub(r"\s+", "", raw)
        return AnalysisStream(
            raw=raw,
            text=b64_clean,
            symbol_class="base64",
            alphabet_size=64,
            preserves_spaces=False,
            preserves_punctuation=False,
        )

    printable = "".join(ch for ch in raw if not ch.isspace())
    return AnalysisStream(
        raw=raw,
        text=printable or raw,
        symbol_class="printable",
        alphabet_size=len(set(printable)) if printable else 0,
        preserves_spaces=" " in raw,
        preserves_punctuation=any(not ch.isalnum() and not ch.isspace() for ch in raw),
    )
