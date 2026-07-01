"""Attack-surface metadata for ciphertext records."""

from __future__ import annotations

from typing import Any

ATTACK_VECTORS = (
    "crib_dragging",
    "brute_force",
    "dictionary",
    "hill_climbing",
    "metaheuristic",
    "side_channel",
)


def _entry(
    viable: str,
    *,
    confidence: float,
    notes: str,
    key_space_estimate: str | int | None = None,
    recommended_methods: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "viable": viable,
        "confidence": round(confidence, 3),
        "notes": notes,
        "key_space_estimate": key_space_estimate,
        "recommended_methods": recommended_methods or [],
    }


def _monoalphabetic_attacks(fingerprint: dict, patterns: dict) -> dict[str, dict]:
    ic_ratio = fingerprint.get("normalized_ic_ratio", 0.0)
    return {
        "crib_dragging": _entry(
            "partial",
            confidence=0.55,
            notes="Short cribs help when spacing/punctuation are preserved.",
            recommended_methods=["known-plaintext fragments", "word boundary anchoring"],
        ),
        "brute_force": _entry(
            "viable",
            confidence=0.9,
            notes="26! substitution search is intractable; frequency-guided hill climb is typical.",
            key_space_estimate="26! (~4e26)",
            recommended_methods=["frequency analysis", "simulated annealing"],
        ),
        "dictionary": _entry(
            "viable" if patterns.get("preserves_spaces") else "partial",
            confidence=0.75 if patterns.get("preserves_spaces") else 0.45,
            notes="Word-aware scoring when spaces survive encryption.",
            recommended_methods=["dictionary scoring", "word length patterns"],
        ),
        "hill_climbing": _entry(
            "viable",
            confidence=0.85,
            notes="Optimize substitution mapping against language model / IC.",
            recommended_methods=["swap-based hill climb", "language model score"],
        ),
        "metaheuristic": _entry(
            "viable",
            confidence=0.8,
            notes="GA/SA over substitution keys with n-gram fitness.",
            recommended_methods=["genetic algorithm", "simulated annealing", "tabu search"],
        ),
        "side_channel": _entry(
            "unknown",
            confidence=0.1,
            notes="Classical pen-and-paper cipher; side channels apply to implementations, not ciphertext alone.",
        ),
    }


def _polyalphabetic_attacks(fingerprint: dict, kasiski: dict, patterns: dict) -> dict[str, dict]:
    periods = kasiski.get("candidate_key_lengths") or []
    friedman = fingerprint.get("friedman_key_length_estimate")
    period_hint = periods or ([int(round(friedman))] if friedman else [])
    return {
        "crib_dragging": _entry(
            "viable",
            confidence=0.85,
            notes="Repeated ciphertext at identical positions across messages enables multi-crib propagation.",
            recommended_methods=["cross-message cribs", "header anchoring"],
        ),
        "brute_force": _entry(
            "partial",
            confidence=0.5,
            notes="Feasible only for short repeating keys; otherwise search is exponential in key length.",
            key_space_estimate="26^m for key length m",
            recommended_methods=["period-first enumeration", "beam search"],
        ),
        "dictionary": _entry(
            "viable" if patterns.get("preserves_spaces") else "partial",
            confidence=0.7,
            notes="Per-column dictionary scoring after period recovery.",
            recommended_methods=["split by period", "dictionary log-likelihood"],
        ),
        "hill_climbing": _entry(
            "viable",
            confidence=0.8,
            notes="Jointly refine key period and shifts with language score.",
            recommended_methods=["Viterbi keystream", "column-wise shift climb"],
        ),
        "metaheuristic": _entry(
            "viable",
            confidence=0.82,
            notes="Metaheuristics excel when Kasiski/Friedman narrow the period.",
            recommended_methods=["PSO over key alphabets", "genetic algorithm on shift vectors"],
            key_space_estimate=f"period candidates: {period_hint}" if period_hint else None,
        ),
        "side_channel": _entry(
            "unknown",
            confidence=0.1,
            notes="Implementation timing/power not observable from ciphertext alone.",
        ),
    }


def _transposition_attacks(patterns: dict) -> dict[str, dict]:
    return {
        "crib_dragging": _entry(
            "partial",
            confidence=0.5,
            notes="Cribs constrain column/row placement in matrix transpositions.",
            recommended_methods=["matrix width search", "crib placement"],
        ),
        "brute_force": _entry(
            "partial",
            confidence=0.45,
            notes="Key space depends on route/keyword size; factorial for column orders.",
            key_space_estimate="factorial in column count",
            recommended_methods=["route enumeration", "keyword permutation"],
        ),
        "dictionary": _entry(
            "viable" if patterns.get("preserves_spaces") else "partial",
            confidence=0.65,
            notes="Anagram scoring with dictionary when letters are preserved.",
            recommended_methods=["anagram search", "word segmentation"],
        ),
        "hill_climbing": _entry(
            "viable",
            confidence=0.75,
            notes="Swap columns/rows to maximize language score.",
            recommended_methods=["column swap climb", "route refinement"],
        ),
        "metaheuristic": _entry(
            "viable",
            confidence=0.78,
            notes="Permutation optimization over column orders or rails.",
            recommended_methods=["simulated annealing", "genetic algorithm"],
        ),
        "side_channel": _entry("unknown", confidence=0.1, notes="Not applicable to ciphertext-only analysis."),
    }


def _encoding_attacks() -> dict[str, dict]:
    return {
        "crib_dragging": _entry("not_applicable", confidence=0.95, notes="Encoding is reversible without cribs."),
        "brute_force": _entry("not_applicable", confidence=0.95, notes="No key space; direct decode."),
        "dictionary": _entry("not_applicable", confidence=0.95, notes="Not a language cipher."),
        "hill_climbing": _entry("not_applicable", confidence=0.95, notes="Direct decode."),
        "metaheuristic": _entry("not_applicable", confidence=0.95, notes="Direct decode."),
        "side_channel": _entry("unknown", confidence=0.1, notes="Not applicable."),
    }


def _modern_attacks(family: str, symbol_class: str) -> dict[str, dict]:
    side = "partial" if family in {"aes_gcm", "aes_cbc", "aes_ctr", "chacha20_poly1305", "triple_des", "fernet"} else "unknown"
    return {
        "crib_dragging": _entry(
            "not_applicable",
            confidence=0.9,
            notes="Modern AEAD/block ciphers resist crib-only classical attacks.",
        ),
        "brute_force": _entry(
            "not_viable",
            confidence=0.99,
            notes="Key space far too large for brute force.",
            key_space_estimate="2^128+",
        ),
        "dictionary": _entry(
            "not_applicable",
            confidence=0.9,
            notes="Ciphertext indistinguishable from random under correct usage.",
        ),
        "hill_climbing": _entry(
            "not_viable",
            confidence=0.95,
            notes="No smooth language score landscape for modern cipher output.",
        ),
        "metaheuristic": _entry(
            "not_viable",
            confidence=0.95,
            notes="Key recovery requires structural breaks, not language optimization.",
        ),
        "side_channel": _entry(
            side,
            confidence=0.55 if side == "partial" else 0.2,
            notes="Timing, cache, power, and fault attacks target implementations.",
            recommended_methods=["timing analysis", "cache attacks", "differential fault analysis"],
        ),
    }


def _hash_attacks() -> dict[str, dict]:
    return {
        "crib_dragging": _entry("not_applicable", confidence=0.99, notes="One-way digest."),
        "brute_force": _entry(
            "partial",
            confidence=0.4,
            notes="Preimage/collision search only for weak or truncated hashes.",
            key_space_estimate="2^256 for SHA-256 preimage",
        ),
        "dictionary": _entry(
            "viable",
            confidence=0.7,
            notes="Rainbow tables / dictionary for unsalted password hashes.",
            recommended_methods=["dictionary", "rainbow tables"],
        ),
        "hill_climbing": _entry("not_viable", confidence=0.9, notes="No gradient toward preimage."),
        "metaheuristic": _entry("partial", confidence=0.35, notes="Heuristic collision search for broken hashes only."),
        "side_channel": _entry(
            "partial",
            confidence=0.5,
            notes="Implementation leaks (HMAC timing, MAC verification) may apply.",
            recommended_methods=["timing attacks on MAC compare"],
        ),
    }


def _asymmetric_attacks(family: str) -> dict[str, dict]:
    return {
        "crib_dragging": _entry("not_applicable", confidence=0.9, notes="No classical crib model."),
        "brute_force": _entry(
            "not_viable",
            confidence=0.99,
            notes="Discrete log / factoring hard.",
            key_space_estimate="2^256+",
        ),
        "dictionary": _entry("not_applicable", confidence=0.9, notes="Not language-encoded."),
        "hill_climbing": _entry("not_viable", confidence=0.95, notes="Discrete log / factoring hard."),
        "metaheuristic": _entry("not_viable", confidence=0.95, notes="No viable fitness landscape."),
        "side_channel": _entry(
            "viable" if family in {"rsa", "ed25519", "x25519"} else "partial",
            confidence=0.65,
            notes="Lattice/fault/timing attacks on implementations.",
            recommended_methods=["timing", "fault injection", "power analysis"],
        ),
    }


def _unsolved_attacks(fingerprint: dict, kasiski: dict) -> dict[str, dict]:
    return {
        "crib_dragging": _entry(
            "viable",
            confidence=0.9,
            notes="Universal header anomaly and in-depth alignment support multi-message cribs.",
            recommended_methods=["depth crib-drag", "cross-message propagation"],
        ),
        "brute_force": _entry(
            "partial",
            confidence=0.35,
            notes="Deck size 83 with shared keystream; column-wise search may be bounded.",
            key_space_estimate="83^T position keystream",
        ),
        "dictionary": _entry(
            "partial",
            confidence=0.45,
            notes="Flat unigram limits naive dictionary scoring; depth differencing helps.",
            recommended_methods=["Markov scoring", "depth Viterbi"],
        ),
        "hill_climbing": _entry(
            "partial",
            confidence=0.5,
            notes="Keystream recovery under language model when distribution is non-uniform.",
            recommended_methods=["column shift climb", "Viterbi MAP keystream"],
        ),
        "metaheuristic": _entry(
            "viable",
            confidence=0.75,
            notes="PRNG seed search and combiner sweeps (EyeStat/EyeSieve model).",
            recommended_methods=["PRNG seed scan", "combiner sweep", "GPU metaheuristic"],
        ),
        "side_channel": _entry(
            "unknown",
            confidence=0.15,
            notes="Game asset extraction may leak implementation details outside ciphertext.",
        ),
    }


FAMILY_GROUPS = {
    "monoalphabetic": {"atbash", "caesar", "affine", "substitution", "polybius", "homophonic", "nomenclator"},
    "polyalphabetic": {
        "vigenere",
        "beaufort",
        "porta",
        "gronsfeld",
        "autokey",
        "running_key",
        "noita-eye",
    },
    "transposition": {"railfence", "columnar"},
    "polygraphic": {"playfair", "four_square", "hill"},
    "fractionated": {"adfgx", "adfgvx", "bifid", "trifid", "straddle_checkerboard", "fractionated_morse"},
    "encoding": {"base64", "baconian"},
}


def attack_surface(
    *,
    cipher_family: str,
    era: str,
    status: str,
    fingerprint: dict,
    kasiski: dict,
    patterns: dict,
    params: dict | None = None,
) -> dict[str, dict]:
    if status == "unsolved" or cipher_family == "noita-eye":
        return _unsolved_attacks(fingerprint, kasiski)

    if era == "modern":
        if cipher_family in {"sha256", "sha512", "sha3_256", "blake2b", "hmac"}:
            return _hash_attacks()
        if cipher_family in {"rsa", "ed25519", "x25519"}:
            return _asymmetric_attacks(cipher_family)
        return _modern_attacks(cipher_family, fingerprint.get("symbol_class", "printable"))

    if cipher_family in FAMILY_GROUPS["encoding"]:
        return _encoding_attacks()
    if cipher_family in FAMILY_GROUPS["transposition"]:
        return _transposition_attacks(patterns)
    if cipher_family in FAMILY_GROUPS["polyalphabetic"]:
        return _polyalphabetic_attacks(fingerprint, kasiski, patterns)
    if cipher_family in FAMILY_GROUPS["polygraphic"] or cipher_family in FAMILY_GROUPS["fractionated"]:
        return _polyalphabetic_attacks(fingerprint, kasiski, patterns)
    if cipher_family in FAMILY_GROUPS["monoalphabetic"]:
        return _monoalphabetic_attacks(fingerprint, patterns)

    return _polyalphabetic_attacks(fingerprint, kasiski, patterns)
