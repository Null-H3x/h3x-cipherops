"""GAK / XGAK dynamic substitution ciphers (Eyes / Noita cryptanalysis model).

Ported from Null-H3x/Eyes ``eyestat/eyestat_kernels.py`` (gak_encrypt / gak_decrypt).
See docs/math-formulas/gak.md and docs/math-formulas/xgak.md.
"""

from __future__ import annotations

import random
from typing import Literal

from cipherops.ciphers.utils import char_index, clean_alpha, index_char

# Mode codes (match Eyes eyestat_kernels.py)
GAK_CTAK_RIGHT = 0
GAK_CTAK_LEFT = 1
GAK_PTAK_RIGHT = 2
GAK_PTAK_LEFT = 3
XGAK_SUM_RIGHT = 4
XGAK_SUM_LEFT = 5
XGAK_DIFF_RIGHT = 6
XGAK_DIFF_LEFT = 7

GakModeName = Literal[
    "ctak_right",
    "ctak_left",
    "ptak_right",
    "ptak_left",
    "xgak_sum_right",
    "xgak_sum_left",
    "xgak_diff_right",
    "xgak_diff_left",
]

MODE_BY_NAME: dict[str, int] = {
    "ctak_right": GAK_CTAK_RIGHT,
    "ctak_left": GAK_CTAK_LEFT,
    "ptak_right": GAK_PTAK_RIGHT,
    "ptak_left": GAK_PTAK_LEFT,
    "xgak_sum_right": XGAK_SUM_RIGHT,
    "xgak_sum_left": XGAK_SUM_LEFT,
    "xgak_diff_right": XGAK_DIFF_RIGHT,
    "xgak_diff_left": XGAK_DIFF_LEFT,
}


def perm_inverse(p: list[int]) -> list[int]:
    q = [0] * len(p)
    for i, val in enumerate(p):
        q[val] = i
    return q


def random_perm(n: int, rng: random.Random) -> list[int]:
    p = list(range(n))
    rng.shuffle(p)
    return p


def generate_sigma_tables(prng_seed: int, n: int) -> list[list[int]]:
    """N+1 permutations in S_n from deterministic PRNG seed (Eyes keygen model)."""
    rng = random.Random(prng_seed)
    return [random_perm(n, rng) for _ in range(n + 1)]


def gak_encrypt_ints(pt: list[int], sigma: list[list[int]], n: int, mode: int) -> list[int]:
    active = sigma[0][:]
    ct: list[int] = []
    for p in pt:
        c = active[p]
        ct.append(c)
        if mode in (GAK_CTAK_RIGHT, GAK_CTAK_LEFT):
            k = c
        elif mode in (GAK_PTAK_RIGHT, GAK_PTAK_LEFT):
            k = p
        elif mode in (XGAK_SUM_RIGHT, XGAK_SUM_LEFT):
            k = (p + c) % n
        elif mode in (XGAK_DIFF_RIGHT, XGAK_DIFF_LEFT):
            k = (c - p) % n
        else:
            raise ValueError(f"Unknown GAK mode: {mode}")
        s_k = sigma[k]
        if mode in (GAK_CTAK_RIGHT, GAK_PTAK_RIGHT, XGAK_SUM_RIGHT, XGAK_DIFF_RIGHT):
            active = [active[s_k[i]] for i in range(n)]
        else:
            active = [s_k[active[i]] for i in range(n)]
    return ct


def gak_decrypt_ints(ct: list[int], sigma: list[list[int]], n: int, mode: int) -> list[int]:
    active = sigma[0][:]
    active_inv = perm_inverse(active)
    pt: list[int] = []
    for c in ct:
        p = active_inv[c]
        pt.append(p)
        if mode in (GAK_CTAK_RIGHT, GAK_CTAK_LEFT):
            k = c
        elif mode in (GAK_PTAK_RIGHT, GAK_PTAK_LEFT):
            k = p
        elif mode in (XGAK_SUM_RIGHT, XGAK_SUM_LEFT):
            k = (p + c) % n
        elif mode in (XGAK_DIFF_RIGHT, XGAK_DIFF_LEFT):
            k = (c - p) % n
        else:
            raise ValueError(f"Unknown GAK mode: {mode}")
        s_k = sigma[k]
        if mode in (GAK_CTAK_RIGHT, GAK_PTAK_RIGHT, XGAK_SUM_RIGHT, XGAK_DIFF_RIGHT):
            active = [active[s_k[i]] for i in range(n)]
        else:
            active = [s_k[active[i]] for i in range(n)]
        active_inv = perm_inverse(active)
    return pt


def gak_encrypt_text(
    text: str,
    *,
    mode: GakModeName,
    prng_seed: int,
    alphabet_size: int = 26,
) -> str:
    """Encrypt A–Z text under GAK/xGAK; preserve spaces and punctuation."""
    mode_code = MODE_BY_NAME[mode]
    sigma = generate_sigma_tables(prng_seed, alphabet_size)
    out: list[str] = []
    ai = 0
    alpha = clean_alpha(text)
    pt_ints = [char_index(ch) for ch in alpha]
    ct_ints = gak_encrypt_ints(pt_ints, sigma, alphabet_size, mode_code)
    for ch in text:
        if ch.isalpha():
            out.append(index_char(ct_ints[ai], upper=ch.isupper()))
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def gak_decrypt_text(
    text: str,
    *,
    mode: GakModeName,
    prng_seed: int,
    alphabet_size: int = 26,
) -> str:
    mode_code = MODE_BY_NAME[mode]
    sigma = generate_sigma_tables(prng_seed, alphabet_size)
    out: list[str] = []
    ai = 0
    alpha = clean_alpha(text)
    ct_ints = [char_index(ch) for ch in alpha]
    pt_ints = gak_decrypt_ints(ct_ints, sigma, alphabet_size, mode_code)
    for ch in text:
        if ch.isalpha():
            out.append(index_char(pt_ints[ai], upper=ch.isupper()))
            ai += 1
        else:
            out.append(ch)
    return "".join(out)
