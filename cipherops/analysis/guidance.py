"""Cipher-family analysis guidance — when periodic tools apply."""

from __future__ import annotations

NON_PERIODIC_POLYALPHABETIC = frozenset({"autokey", "running_key", "gronsfeld_autokey", "gak"})


def _seed_length(params: dict | None) -> int:
    params = params or {}
    if params.get("numeric_key"):
        return len(str(params["numeric_key"]))
    key = params.get("key") or "KEY"
    alpha_key = "".join(ch for ch in str(key) if ch.isalpha())
    return len(alpha_key) if alpha_key else len(str(key))


def _autokey_regime(message_length: int, seed_len: int) -> str:
    if message_length <= seed_len:
        return "seed_dominated"
    if message_length <= seed_len * 2:
        return "mixed"
    return "otp_like"


def analysis_guidance(
    cipher_family: str,
    *,
    message_length: int,
    params: dict | None = None,
    fingerprint: dict | None = None,
) -> dict | None:
    """Return family-specific guidance for interpreting statistical metrics."""
    family = cipher_family.replace("-", "_")
    fingerprint = fingerprint or {}

    if family in {"autokey", "gronsfeld_autokey"}:
        seed_len = _seed_length(params)
        regime = _autokey_regime(message_length, seed_len)
        extension = params.get("extension", "plaintext")
        variant = params.get("variant", "standard")
        label = "autokey" if family == "autokey" else "Gronsfeld autokey"
        if family == "autokey":
            label = f"autokey ({extension}, {variant})"
        return {
            "periodicity": "non_periodic",
            "coset_ic_applicable": False,
            "kasiski_applicable": False,
            "friedman_applicable": False,
            "seed_length": seed_len,
            "regime": regime,
            "extension": extension,
            "variant": variant if family == "autokey" else None,
            "cipher_label": label,
            "warnings": [
                "Do not apply Vigenère period recovery (Kasiski/Friedman/coset IC).",
                "Long ciphertext IC approaches English (~0.067), not polyalphabetic (~0.038).",
            ]
            + (
                ["Ciphertext-autokey: keystream extends with prior ciphertext, not plaintext."]
                if extension == "ciphertext"
                else []
            ),
            "recommended_workflow": [
                "Brute-force or crib the priming key (first |K| positions) if message is short.",
                "Known-plaintext: decrypt iteratively — each recovered letter extends keystream.",
                "Ciphertext-only after seed: treat as OTP-like without cribs or book/key reuse.",
            ],
        }

    if family == "gak":
        mode = params.get("mode", "ctak_right")
        is_xgak = mode.startswith("xgak_")
        return {
            "periodicity": "non_periodic",
            "coset_ic_applicable": False,
            "kasiski_applicable": False,
            "friedman_applicable": False,
            "regime": "dynamic_substitution",
            "mode": mode,
            "cipher_label": "XGAK (Eyes)" if is_xgak else "GAK (Eyes)",
            "warnings": [
                "Dynamic permutation cipher (Eyes model) — not Vigenère/autokey mod-26 addition.",
                "Key material: PRNG seed → N+1 permutations σ[0..N] in S_N.",
                "Do not apply periodic polyalphabetic period recovery.",
            ],
            "recommended_workflow": [
                "Brute PRNG seed if search space is small (Noita hypothesis).",
                "For mod-N: ct[p] = active[p]; active advances via σ[k] where k from pt, ct, or (pt±ct).",
                "See Null-H3x/Eyes eyestat_kernels.py and docs/math-formulas/gak.md.",
            ],
        }

    if family == "running_key":
        return {
            "periodicity": "non_periodic",
            "coset_ic_applicable": False,
            "kasiski_applicable": False,
            "friedman_applicable": False,
            "regime": "book_keystream",
            "warnings": [
                "Keystream does not repeat; periodic polyalphabetic attacks do not apply.",
                "Security depends on key text entropy and reuse — not key length alone.",
            ],
            "recommended_workflow": [
                "Identify key source (book, article) via crib or stylometric match.",
                "Align keystream offset once source is found.",
                "If key text is unknown, search candidate books/pages (external corpus required).",
            ],
        }

    return None
