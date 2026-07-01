"""Brute-force keyspace estimates per cipher family."""

from __future__ import annotations

import math


def _fmt(n: int | float) -> str:
    if isinstance(n, float):
        return f"{n:.4g}"
    if n >= 1_000_000:
        return f"{n:.4e}".replace("e+0", "e")
    return str(n)


def estimate_keyspace(cipher_family: str, *, params: dict | None = None) -> dict:
    """Return keyspace estimate for attack metadata."""
    params = params or {}
    family = cipher_family.replace("-", "_")

    if family in {"atbash"}:
        return {"exact": 1, "formula": "1", "log2": 0.0, "label": "1"}

    if family in {"caesar"}:
        return {"exact": 25, "formula": "26-1", "log2": math.log2(25), "label": "25"}

    if family == "affine":
        return {"exact": 312, "formula": "φ(26)×26 = 12×26", "log2": math.log2(312), "label": "312"}

    if family in {"vigenere", "beaufort", "autokey", "running_key", "porta"}:
        key = params.get("key") or params.get("numeric_key") or ""
        m = len(str(key)) if key else params.get("period", 3)
        if family == "gronsfeld" or params.get("numeric_key"):
            space = 10 ** m
            return {"exact": space, "formula": f"10^{m}", "log2": m * math.log2(10), "label": f"10^{m}"}
        if family == "porta":
            space = 13 ** m
            return {"exact": None, "formula": f"13^{m}", "log2": m * math.log2(13), "label": f"13^{m}"}
        space = 26 ** m
        return {"exact": None, "formula": f"26^{m}", "log2": m * math.log2(26), "label": f"26^{m}"}

    if family == "gronsfeld":
        m = len(str(params.get("numeric_key", "31415")))
        return {"exact": 10 ** m, "formula": f"10^{m}", "log2": m * math.log2(10), "label": f"10^{m}"}

    if family in {"substitution", "homophonic", "nomenclator"}:
        return {
            "exact": None,
            "formula": "26!",
            "log2": math.lgamma(27) / math.log(2),
            "label": "26! (~4e26)",
        }

    if family == "railfence":
        rails = params.get("rails", 3)
        return {"exact": None, "formula": f"route over {rails} rails", "log2": None, "label": f"rails={rails}"}

    if family == "columnar":
        k = len(str(params.get("key", "KEYWORD")))
        fact = math.factorial(k)
        return {"exact": fact, "formula": f"{k}!", "log2": math.lgamma(k + 1) / math.log(2), "label": f"{k}!"}

    if family in {"playfair", "four_square", "polybius"}:
        return {"exact": None, "formula": "≈25!", "log2": math.lgamma(26) / math.log(2), "label": "≈25!"}

    if family == "hill":
        return {"exact": 157248, "formula": "invertible 2×2 mod 26", "log2": math.log2(157248), "label": "157248 (2×2)"}

    if family in {"adfgx", "adfgvx", "bifid", "trifid", "straddle_checkerboard", "fractionated_morse"}:
        return {"exact": None, "formula": "compound (polybius × transposition)", "log2": None, "label": "compound stages"}

    if family in {"base64", "baconian"}:
        return {"exact": 1, "formula": "encoding", "log2": 0.0, "label": "1 (decode)"}

    if family == "noita_eye":
        deck = params.get("deck_size", 83)
        t = params.get("max_length", 137)
        return {
            "exact": None,
            "formula": f"{deck}^T position keystream",
            "log2": t * math.log2(deck),
            "label": f"{deck}^{t}",
        }

    if family.startswith("aes") or family in {"chacha20_poly1305", "fernet", "xor_stream", "pbkdf2", "hkdf", "triple_des"}:
        bits = params.get("key_bits", 128)
        return {"exact": None, "formula": f"2^{bits}", "log2": float(bits), "label": f"2^{bits}"}

    if family in {"rsa", "ed25519", "x25519"}:
        return {"exact": None, "formula": "2^128+", "log2": 128.0, "label": "2^128+"}

    if family in {"sha256", "sha512", "sha3_256", "blake2b", "hmac"}:
        bits = params.get("output_bits", 256)
        return {"exact": None, "formula": f"2^{bits} preimage", "log2": float(bits), "label": f"2^{bits} preimage"}

    return {"exact": None, "formula": "unknown", "log2": None, "label": "unknown"}
