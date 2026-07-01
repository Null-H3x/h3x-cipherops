"""Symbol substitution ciphers (Pigpen / Masonic cipher)."""

from __future__ import annotations

from cipherops.ciphers.utils import clean_alpha

# Unique Unicode symbols per letter (standard 26-cell Pigpen / Masonic chart order).
_PIGPEN_SYMBOLS = (
    "⌈⌊⌉⌋⊿⊣⊢⊥⊤◸◹◺◻◼◽◾◿▘▝▗▖▌▐▎▏▁▂▃▄▅▆▇"
)
_ENCODE = {chr(ord("A") + i): _PIGPEN_SYMBOLS[i] for i in range(26)}
_DECODE = {sym: letter for letter, sym in _ENCODE.items()}


def pigpen_encode(text: str) -> str:
    """Map A–Z to distinct Pigpen cell symbols; preserve spaces and punctuation."""
    alpha = clean_alpha(text)
    ai = 0
    out: list[str] = []
    for ch in text:
        if ch.isalpha():
            out.append(_ENCODE[alpha[ai]])
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def pigpen_decode(text: str) -> str:
    """Decode Pigpen symbols; non-symbol characters pass through."""
    out: list[str] = []
    for ch in text:
        if ch in _DECODE:
            out.append(_DECODE[ch])
        else:
            out.append(ch)
    return "".join(out)
