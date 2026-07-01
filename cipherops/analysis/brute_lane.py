"""Dashboard brute-force lanes — cheap attacks before / after constraint loop."""

from __future__ import annotations

from typing import Any, Literal

from cipherops.analysis.autokey_solver import (
    _english_score,
    brute_force_autokey_seed,
    brute_force_gronsfeld_autokey_seed,
)
from cipherops.ciphers import gak as gak_cipher
from cipherops.ciphers.classical import autokey_decrypt, caesar
from cipherops.ciphers.utils import clean_alpha
from cipherops.constraints.dynamic_perm import _simulate_encrypt_path
from cipherops.constraints.domain import plaintext_as_ints

BruteLane = Literal["auto", "caesar", "autokey_seed", "gak_prng"]


def _caesar_sweep(ciphertext: str, *, top_n: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for shift in range(26):
        plain = caesar(ciphertext, shift)
        score = _english_score(plain)
        results.append(
            {
                "lane": "caesar",
                "key": shift,
                "label": f"ROT{shift}",
                "score": round(score, 4),
                "plaintext_preview": plain[:120],
                "plaintext": plain,
            }
        )
    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:top_n]


def _autokey_sweep(
    ciphertext: str,
    *,
    seed_length: int,
    top_n: int,
    family: str = "autokey",
    variant: str = "standard",
    extension: str = "plaintext",
) -> list[dict[str, Any]]:
    if family == "gronsfeld_autokey":
        hits = brute_force_gronsfeld_autokey_seed(
            ciphertext, seed_length, extension=extension, top_n=top_n
        )
    else:
        hits = brute_force_autokey_seed(
            ciphertext,
            seed_length,
            variant=variant,
            extension=extension,
            top_n=top_n,
        )
    out: list[dict[str, Any]] = []
    for rank, hit in enumerate(hits):
        out.append(
            {
                "lane": "autokey_seed",
                "rank": rank,
                "key": hit["seed"],
                "label": f"seed={hit['seed']}",
                "score": round(hit["score"], 4),
                "plaintext_preview": hit["plaintext"][:120],
                "plaintext": hit["plaintext"],
                "hypothesis_patch": {
                    "seed": hit["seed"],
                    "seed_length": seed_length,
                    "family": family,
                    "variant": variant,
                    "extension": extension,
                },
            }
        )
    return out


def _gak_prng_sweep(
    ciphertext: str,
    *,
    mode: str,
    seed_min: int,
    seed_max: int,
    top_n: int,
    plaintext_trial: str | None = None,
    alphabet_size: int = 26,
) -> list[dict[str, Any]]:
    mode_code = gak_cipher.MODE_BY_NAME[mode]
    ct_ints = [ord(ch) - ord("A") for ch in clean_alpha(ciphertext)]
    pt_ints = plaintext_as_ints(plaintext_trial)
    compare_len = len(ct_ints)
    if pt_ints is not None:
        compare_len = min(compare_len, len(pt_ints))

    survivors: list[dict[str, Any]] = []
    for seed in range(seed_min, seed_max + 1):
        sigma = gak_cipher.generate_sigma_tables(seed, alphabet_size)
        ok = False
        detail = "roundtrip"
        preview: str | None = None
        if pt_ints is not None and compare_len > 0:
            trial_pt = pt_ints[:compare_len]
            enc_ct, _ = _simulate_encrypt_path(trial_pt, sigma, alphabet_size, mode_code)
            ok = enc_ct == ct_ints[:compare_len]
            detail = "encrypt_verify"
        else:
            try:
                dec = gak_cipher.gak_decrypt_ints(ct_ints[:compare_len], sigma, alphabet_size, mode_code)
                enc_back, _ = _simulate_encrypt_path(dec, sigma, alphabet_size, mode_code)
                ok = enc_back == ct_ints[:compare_len]
                if ok and dec:
                    preview = "".join(chr(d + ord("A")) for d in dec[: min(40, len(dec))])
            except ValueError:
                ok = False
        if ok:
            survivors.append(
                {
                    "lane": "gak_prng",
                    "key": seed,
                    "label": f"prng_seed={seed}",
                    "score": 1.0,
                    "detail": detail,
                    "plaintext_preview": preview,
                    "hypothesis_patch": {"mode": mode, "prng_seed": seed},
                }
            )

    return survivors[:top_n]


def resolve_lane(
    lane: BruteLane,
    *,
    propagator: str | None,
    classification: dict[str, Any] | None,
) -> BruteLane:
    if lane != "auto":
        return lane
    if propagator == "stream_extension":
        return "autokey_seed"
    if propagator == "dynamic_perm":
        return "gak_prng"
    if classification and classification.get("profile", {}).get("symbol_class") == "alpha":
        ic_band = classification.get("profile", {}).get("ic_band")
        if ic_band == "language_like":
            return "caesar"
        if ic_band == "flat_polyalphabetic":
            return "autokey_seed"
    return "caesar"


def run_brute_lane(
    *,
    ciphertext: str,
    lane: BruteLane = "auto",
    propagator: str | None = None,
    classification: dict[str, Any] | None = None,
    hypothesis: dict[str, Any] | None = None,
    seed_length: int = 3,
    top_n: int = 10,
    gak_mode: str = "ctak_right",
    gak_seed_min: int = 0,
    gak_seed_max: int = 500,
    plaintext_trial: str | None = None,
) -> dict[str, Any]:
    """Run a brute lane and return ranked candidates."""
    ct = (ciphertext or "").strip()
    if not ct or not clean_alpha(ct):
        raise ValueError("Alphabetic ciphertext required for brute lanes")

    hyp = dict(hypothesis or {})
    resolved = resolve_lane(lane, propagator=propagator, classification=classification)
    candidates: list[dict[str, Any]] = []

    if resolved == "caesar":
        candidates = _caesar_sweep(ct, top_n=top_n)
    elif resolved == "autokey_seed":
        candidates = _autokey_sweep(
            ct,
            seed_length=int(hyp.get("seed_length", seed_length)),
            top_n=top_n,
            family=str(hyp.get("family", "autokey")),
            variant=str(hyp.get("variant", "standard")),
            extension=str(hyp.get("extension", "plaintext")),
        )
    elif resolved == "gak_prng":
        if gak_seed_max - gak_seed_min > 5000:
            raise ValueError("GAK PRNG sweep limited to 5000 seeds per request")
        candidates = _gak_prng_sweep(
            ct,
            mode=str(hyp.get("mode", gak_mode)),
            seed_min=gak_seed_min,
            seed_max=gak_seed_max,
            top_n=top_n,
            plaintext_trial=plaintext_trial,
            alphabet_size=int(hyp.get("alphabet_size", 26)),
        )
    else:
        raise ValueError(f"Unknown brute lane: {resolved}")

    return {
        "lane": resolved,
        "requested_lane": lane,
        "propagator": propagator,
        "count": len(candidates),
        "candidates": candidates,
        "notes": _lane_notes(resolved),
    }


def _lane_notes(lane: BruteLane) -> str:
    notes = {
        "caesar": "26-shift sweep scored by English unigrams — best after language-like IC.",
        "autokey_seed": "Enumerates 26^n priming keys; use short seed_length (≤4). Promote seed → re-run loop.",
        "gak_prng": "PRNG seed sweep with roundtrip or encrypt-verify; widen range or add plaintext trial.",
    }
    return notes.get(lane, "")
